//! Real CLI, authenticated named chunk stream and bounded HTTP, inside disposable loopback.

use std::{fs, net::Ipv4Addr, process::Stdio, time::Duration};

use tokio::{
    io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader},
    net::{TcpStream, UnixListener},
    process::Command,
    time::timeout,
};
use volparossa_content::site::{SITE_CONTENT_TYPE, SiteAsset, SiteBundle};

use super::{Fault, Fixture, NAME, directory_names, isolated_network};

#[path = "browser.rs"]
mod browser;

#[test]
fn site_cli_delivers_signed_html_assets_ranges_and_cleans_up() {
    isolated_network(
        "site::site_cli_delivers_signed_html_assets_ranges_and_cleans_up",
        successful_site(),
        "loopback",
    );
}

fn site_fixture() -> Fixture {
    let mut fixture = Fixture::new();
    fixture.content_type = SITE_CONTENT_TYPE;
    fixture.bytes = SiteBundle::encode(vec![
        SiteAsset {
            path: "/index.html".into(),
            content_type: "text/html".into(),
            bytes: b"<!doctype html><link rel=stylesheet href=/assets/main.css?v=1><h1>Verified site</h1><script src=/assets/main.js?v=1></script>".to_vec(),
        },
        SiteAsset {
            path: "/assets/main.css".into(),
            content_type: "text/css".into(),
            bytes: b"body{font-family:sans-serif;padding:30px}h1{color:green}".to_vec(),
        },
        SiteAsset {
            path: "/assets/main.js".into(),
            content_type: "text/javascript".into(),
            bytes: b"document.querySelector('h1').textContent='VOLPAROSSA: JavaScript from the verified cache';document.title='Verified native site'".to_vec(),
        },
        SiteAsset {
            path: "/chapter/index.html".into(),
            content_type: "text/html".into(),
            bytes: b"<h1>Chapter</h1>".to_vec(),
        },
    ]).unwrap();
    fixture
}

async fn successful_site() {
    let mut fixture = site_fixture();
    let browser_artifact = std::env::var_os("VOLPAROSSA_SITE_BROWSER_ARTIFACT");
    let lifetime = if browser_artifact.is_some() {
        "60"
    } else {
        "3"
    };
    let root = fixture.directory.path().to_owned();
    let listener = UnixListener::bind(root.join("control.sock")).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_volparossa"))
        .current_dir(&root)
        .env("TMPDIR", &root)
        .arg("--control-socket")
        .arg(root.join("control.sock"))
        .args(["content", "site", "open", "--publisher-key"])
        .arg(hex::encode(fixture.key.verifying_key().to_bytes()))
        .args(["--name", NAME, "--cache"])
        .arg(root.join("agent-cache"))
        .args(["--min-free-bytes", "0", "--lifetime-seconds", lifetime])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    timeout(Duration::from_secs(15), async {
        let ((), read) = tokio::join!(
            fixture.serve(&listener, Fault::None, false),
            output.read_line(&mut line)
        );
        assert!(
            read.unwrap() > 0,
            "site CLI must emit ready only after final verified transfer"
        );
    })
    .await
    .unwrap();
    drop(listener);
    fs::remove_file(root.join("control.sock")).unwrap();
    let ready: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(ready["operation"], "native_site_ready");
    assert_eq!(ready["assets"], 4);
    assert_eq!(ready["name"], NAME);
    assert_eq!(ready["native_publisher_authenticated"], true);
    assert_eq!(ready["https_origin_authenticated"], false);
    assert_eq!(ready["static_only"], true);
    assert_eq!(ready["automatic_browser_open"], false);
    assert_eq!(ready["peer_bytes"], fixture.bytes.len());
    let url = ready["site_url"].as_str().unwrap();
    let host = url
        .strip_prefix("http://")
        .unwrap()
        .strip_suffix('/')
        .unwrap();
    let (domain, port) = host.rsplit_once(':').unwrap();
    assert!(domain.starts_with("vp") && domain.ends_with(".localhost"));
    assert_eq!(domain.len(), 2 + 32 + ".localhost".len());
    let port = port.parse::<u16>().unwrap();
    let bundle = SiteBundle::decode(fixture.bytes.clone()).unwrap();
    check_assets(port, host, &bundle).await;
    if let Some(artifact) = browser_artifact {
        browser::render(url, &root, std::path::Path::new(&artifact)).await;
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(i32::try_from(child.id().unwrap()).unwrap()),
            nix::sys::signal::Signal::SIGTERM,
        )
        .unwrap();
    }
    line.clear();
    timeout(Duration::from_secs(5), output.read_line(&mut line))
        .await
        .unwrap()
        .unwrap();
    let closed: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(closed["operation"], "native_site_closed");
    assert_eq!(closed["private_spool_removed"], true);
    let result = timeout(Duration::from_secs(5), child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(directory_names(&root), ["served-store"]);
    assert!(
        TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .is_err()
    );
}

async fn check_assets(port: u16, host: &str, bundle: &SiteBundle) {
    let first = request(port, host, "GET", "/", "").await;
    let (headers, body) = split_response(&first);
    assert!(headers.starts_with("HTTP/1.1 200"));
    let lower = headers.to_ascii_lowercase();
    assert!(lower.contains("content-type: text/html"));
    assert!(lower.contains("cache-control: no-store"));
    assert!(lower.contains("sandbox allow-scripts allow-downloads"));
    assert!(!lower.contains("allow-same-origin"));
    assert_eq!(body, bundle.asset("/index.html").unwrap().bytes);
    for path in ["/assets/main.css", "/assets/main.js"] {
        let response = request(port, host, "GET", path, "").await;
        let (headers, body) = split_response(&response);
        assert!(headers.starts_with("HTTP/1.1 200"));
        assert_eq!(body, bundle.asset(path).unwrap().bytes);
    }
    let response = request(port, host, "GET", "/chapter/", "").await;
    assert_eq!(split_response(&response).1, b"<h1>Chapter</h1>");
    let response = request(port, host, "HEAD", "/assets/main.css", "").await;
    assert!(split_response(&response).0.starts_with("HTTP/1.1 200"));
    assert!(split_response(&response).1.is_empty());
    let response = request(port, host, "GET", "/assets/main.js", "Range: bytes=0-7\r\n").await;
    assert!(split_response(&response).0.starts_with("HTTP/1.1 206"));
    assert_eq!(split_response(&response).1, b"document");
    let response = request(port, "unrelated.localhost", "GET", "/", "").await;
    assert!(!response.windows(12).any(|window| window == b"HTTP/1.1 200"));
    let response = request(port, host, "GET", "/../index.html", "").await;
    assert!(!response.windows(12).any(|window| window == b"HTTP/1.1 200"));
}

async fn request(port: u16, host: &str, method: &str, path: &str, headers: &str) -> Vec<u8> {
    timeout(Duration::from_secs(2), async {
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        stream
            .write_all(
                format!(
                    "{method} {path} HTTP/1.1\r\nHost: {host}\r\n{headers}Connection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        response
    })
    .await
    .unwrap()
}

fn split_response(response: &[u8]) -> (&str, &[u8]) {
    let end = response
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .unwrap();
    (
        std::str::from_utf8(&response[..end]).unwrap(),
        &response[end + 4..],
    )
}
