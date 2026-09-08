//! One explicit cooperative-origin download, not a proxy or another site's browser origin.

use std::{
    io::{Seek as _, Write as _},
    net::{Ipv4Addr, SocketAddr},
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context as _, Result, bail};
use clap::Args;
use rand_core::{OsRng, RngCore as _};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
    signal::unix::{SignalKind, signal},
    time::{Instant, timeout_at},
};

use super::{
    FetchHttps, HttpsSourceChoice, Limits,
    https_download::{self, VerifiedDownload},
    now_seconds,
};

const MAX_REQUEST_BYTES: usize = 8192;
const MAX_ATTEMPTS: usize = 8;
const LINK_LIFETIME: Duration = Duration::from_secs(300);

#[derive(Debug, Args)]
pub(crate) struct Arguments {
    /// Exact cooperative HTTPS resource; never supplied by a localhost HTTP request.
    #[arg(long, value_parser = super::parse_origin_url)]
    url: String,
    /// Canonical same-origin descriptor path for the supported public representation.
    #[arg(long, value_parser = super::parse_metadata_path)]
    metadata_path: String,
    /// Agent-owned cache destination; the browser's temporary spool is separate and private.
    #[arg(long)]
    cache: PathBuf,
    /// Explicitly reopen verified owned chunks after fresh origin authentication.
    #[arg(long)]
    reuse_cache: bool,
    /// Source preference after fresh origin authentication; never grants external origin rights.
    #[arg(long, value_enum, default_value = "auto")]
    source_strategy: HttpsSourceChoice,
    /// Explicit public PEM roots for this operation only; otherwise Debian system roots.
    #[arg(long)]
    ca_file: Option<PathBuf>,
    #[command(flatten)]
    limits: Limits,
}

impl Arguments {
    fn into_fetch(self) -> FetchHttps {
        FetchHttps {
            url: self.url,
            metadata_path: self.metadata_path,
            cache: self.cache,
            reuse_cache: self.reuse_cache,
            source_strategy: self.source_strategy,
            ca_file: self.ca_file,
            limits: self.limits,
            output: None,
            local_output: None,
        }
    }
}

pub(super) async fn run(args: Arguments, socket: &Path) -> Result<()> {
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    tokio::select! {
        result = run_download(args.into_fetch(), socket) => result,
        _ = interrupt.recv() => bail!("browser download interrupted; temporary spool discarded"),
        _ = terminate.recv() => bail!("browser download stopped; temporary spool discarded"),
    }
}

async fn run_download(args: FetchHttps, socket: &Path) -> Result<()> {
    let directory = tempfile::Builder::new()
        .prefix("volparossa-browser-")
        .tempdir()?;
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    let download = https_download::prepare(&args, socket, directory.path()).await?;
    let bridge = Bridge::bind(&download).await?;
    let mut ready = report(&download);
    ready["operation"] = "browser_download_ready".into();
    ready["download_url"] = format!("http://{}{path}", bridge.address, path = bridge.path).into();
    ready["expires_unix_seconds"] = bridge.expires.into();
    emit(&ready)?;
    bridge.serve(&download).await?;
    let mut completed = report(&download);
    completed["operation"] = "browser_content_download".into();
    drop(download);
    directory
        .close()
        .context("cannot remove private browser spool")?;
    completed["private_spool_removed"] = true.into();
    emit(&completed)
}

fn emit(value: &serde_json::Value) -> Result<()> {
    let mut output = std::io::stdout().lock();
    serde_json::to_writer(&mut output, value)?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(())
}

struct Bridge {
    listener: TcpListener,
    address: SocketAddr,
    path: String,
    expires: u64,
    deadline: Instant,
}

impl Bridge {
    async fn bind(download: &VerifiedDownload) -> Result<Self> {
        download.check_live()?;
        let deadline = download
            .authority_deadline()
            .min(Instant::now() + LINK_LIFETIME);
        let expires = download
            .expires()
            .min(now_seconds()?.saturating_add(LINK_LIFETIME.as_secs()));
        let mut token = [0_u8; 32];
        OsRng
            .try_fill_bytes(&mut token)
            .context("cannot create private browser download token")?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        Ok(Self {
            listener,
            address,
            path: format!("/{}", hex::encode(token)),
            expires,
            deadline,
        })
    }

    async fn serve(self, download: &VerifiedDownload) -> Result<()> {
        let host = self.address.to_string();
        for _ in 0..MAX_ATTEMPTS {
            check_window(download, self.deadline, self.expires)?;
            let (mut stream, peer) = timeout_at(self.deadline, self.listener.accept())
                .await
                .context("browser link expired without a completed download")??;
            let request_deadline = self.deadline.min(Instant::now() + Duration::from_secs(5));
            let accepted = timeout_at(
                request_deadline,
                read_request(&mut stream, &host, &self.path),
            )
            .await
            .is_ok_and(|result| result.is_ok_and(|valid| valid));
            if !accepted || !peer.ip().is_loopback() {
                let _ = timeout_at(request_deadline, stream.write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n"
                )).await;
                continue;
            }
            // Consume the only listener before exposing any body, including on a failed write.
            drop(self.listener);
            return timeout_at(
                self.deadline,
                send_download(&mut stream, download, self.deadline, self.expires),
            )
            .await
            .context("browser delivery exceeded original authority or link deadline")?;
        }
        bail!("browser link request limit reached; no file delivered")
    }
}

async fn read_request(stream: &mut TcpStream, host: &str, path: &str) -> Result<bool> {
    let mut bytes = [0_u8; MAX_REQUEST_BYTES];
    let mut length = 0;
    loop {
        let count = stream.read(&mut bytes[length..]).await?;
        if count == 0 {
            return Ok(false);
        }
        length += count;
        if let Some(valid) = valid_request(&bytes[..length], host, path)? {
            return Ok(valid);
        }
        if length == bytes.len() {
            return Ok(false);
        }
    }
}

fn valid_request(bytes: &[u8], host: &str, path: &str) -> Result<Option<bool>> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut request = httparse::Request::new(&mut headers);
    let httparse::Status::Complete(length) = request.parse(bytes)? else {
        return Ok(None);
    };
    if length != bytes.len()
        || request.method != Some("GET")
        || request.version != Some(1)
        || request.path != Some(path)
    {
        return Ok(Some(false));
    }
    let mut hosts = 0;
    for header in request.headers {
        if header.name.eq_ignore_ascii_case("host") {
            hosts += 1;
            if header.value != host.as_bytes() {
                return Ok(Some(false));
            }
        } else if [
            "content-length",
            "transfer-encoding",
            "authorization",
            "proxy-authorization",
            "cookie",
            "origin",
            "range",
            "upgrade",
        ]
        .iter()
        .any(|name| header.name.eq_ignore_ascii_case(name))
        {
            return Ok(Some(false));
        }
    }
    Ok(Some(hosts == 1))
}

fn check_window(download: &VerifiedDownload, deadline: Instant, expires: u64) -> Result<()> {
    download.check_live()?;
    if Instant::now() >= deadline || now_seconds()? >= expires {
        bail!("browser download link expired");
    }
    Ok(())
}

async fn send_download(
    stream: &mut TcpStream,
    download: &VerifiedDownload,
    deadline: Instant,
    expires: u64,
) -> Result<()> {
    check_window(download, deadline, expires)?;
    let length = download.manifest().length();
    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {length}\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"volparossa-download.bin\"\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(headers.as_bytes()).await?;
    let mut file = download.file().try_clone()?;
    file.rewind()?;
    let mut file = tokio::fs::File::from_std(file);
    let mut bytes = vec![0_u8; 65536];
    let mut sent = 0_u64;
    loop {
        let count = file.read(&mut bytes).await?;
        if count == 0 {
            break;
        }
        check_window(download, deadline, expires)?;
        stream.write_all(&bytes[..count]).await?;
        sent += u64::try_from(count)?;
    }
    check_window(download, deadline, expires)?;
    if sent != length {
        bail!("private browser spool changed during delivery");
    }
    stream.shutdown().await?;
    Ok(())
}

fn report(download: &VerifiedDownload) -> serde_json::Value {
    let receipt = download.receipt();
    serde_json::json!({
        "bytes":receipt.bytes, "chunks":receipt.chunks,
        "sha256":hex::encode(download.manifest().object_sha256()),
        "origin_authenticated":true, "authentication_scope":"cooperative-origin",
        "origin_authority_persisted":false, "https_origin_privileges":false, "single_use":true,
        "peer_bytes":receipt.peer_bytes, "origin_body_bytes":receipt.origin_body_bytes,
        "origin_range_requests":receipt.origin_range_requests, "providers_used":receipt.providers_used,
        "provider_peer_ids":receipt.provider_peer_ids, "control_relay_peer_id":receipt.control_relay_peer_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;

    const RESOURCE: &str = "https://origin.example/object.bin";

    #[test]
    fn browser_https_source_strategy_reaches_the_same_typed_download_request() {
        use volparossa_local_control::HttpsSourceStrategy;
        let base = [
            "volparossa",
            "content",
            "browser-download",
            "--url",
            RESOURCE,
            "--metadata-path",
            "/metadata",
            "--cache",
            "/agent/cache",
        ];
        for (choice, expected) in [
            (None, HttpsSourceStrategy::Auto),
            (Some("auto"), HttpsSourceStrategy::Auto),
            (Some("peers-first"), HttpsSourceStrategy::PeersFirst),
            (Some("origin-only"), HttpsSourceStrategy::OriginOnly),
        ] {
            let mut arguments = base.to_vec();
            if let Some(value) = choice {
                arguments.extend(["--source-strategy", value]);
            }
            let crate::CliCommand::Content { command } =
                crate::Cli::try_parse_from(arguments).unwrap().command
            else {
                panic!("content command");
            };
            let super::super::Command::BrowserDownload(args) = *command else {
                panic!("browser download");
            };
            let request = super::super::https_fetch_request(&args.into_fetch()).unwrap();
            assert_eq!(request.source_strategy, expected as i32);
            assert!(request.output.is_empty());
        }
        assert!(
            crate::Cli::try_parse_from(base.into_iter().chain(["--source-strategy", "unverified"]))
                .is_err()
        );
    }

    #[test]
    fn browser_download_parser_and_http_request_are_explicit_and_bounded() {
        let base = [
            "volparossa",
            "content",
            "browser-download",
            "--url",
            RESOURCE,
            "--metadata-path",
            "/metadata",
            "--cache",
            "/agent/cache",
        ];
        let cli = crate::Cli::try_parse_from(base).unwrap();
        let crate::CliCommand::Content { command } = cli.command else {
            panic!("content");
        };
        let super::super::Command::BrowserDownload(args) = *command else {
            panic!("browser download");
        };
        let request = super::super::https_fetch_request(&args.into_fetch()).unwrap();
        assert!(request.output.is_empty());
        for argument in ["--output", "--local-output", "--bind"] {
            assert!(
                crate::Cli::try_parse_from(base.into_iter().chain([argument, "/unwanted"]))
                    .is_err()
            );
        }
        let valid = b"GET /token HTTP/1.1\r\nHost: 127.0.0.1:1234\r\n\r\n";
        assert_eq!(
            valid_request(valid, "127.0.0.1:1234", "/token").unwrap(),
            Some(true)
        );
        assert_eq!(
            valid_request(&valid[..15], "127.0.0.1:1234", "/token").unwrap(),
            None
        );
        for invalid in [
            "GET /other HTTP/1.1\r\nHost: 127.0.0.1:1234\r\n\r\n",
            "GET /token HTTP/1.1\r\nHost: attacker.example\r\n\r\n",
            "POST /token HTTP/1.1\r\nHost: 127.0.0.1:1234\r\n\r\n",
            "GET /token HTTP/1.1\r\nHost: 127.0.0.1:1234\r\nHost: 127.0.0.1:1234\r\n\r\n",
            "GET /token HTTP/1.1\r\nHost: 127.0.0.1:1234\r\nOrigin: https://other.example\r\n\r\n",
            "GET /token HTTP/1.1\r\nHost: 127.0.0.1:1234\r\nRange: bytes=0-10\r\n\r\n",
            "GET /token HTTP/1.1\r\nHost: 127.0.0.1:1234\r\nContent-Length: 1\r\n\r\nx",
        ] {
            assert_ne!(
                valid_request(invalid.as_bytes(), "127.0.0.1:1234", "/token").unwrap(),
                Some(true)
            );
        }
    }
}
