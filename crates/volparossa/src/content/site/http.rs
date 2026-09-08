//! Bounded single-request HTTP for an already authenticated immutable native bundle.
//! No forwarding, credentials, mutation, service workers, persistent origin or filesystem lookup.

use std::{ops::Range, time::Duration};

use anyhow::{Context as _, Result, bail};
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _},
    time::{Instant, timeout_at},
};
use volparossa_content::site::{MAX_SITE_PATH_BYTES, SiteBundle};

const MAX_HEADERS: usize = 8192;
const SECURITY: &str = concat!(
    "Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n",
    "Referrer-Policy: no-referrer\r\nConnection: close\r\n",
    "Access-Control-Allow-Origin: *\r\n",
    "Access-Control-Expose-Headers: Content-Range, Accept-Ranges, Content-Length\r\n",
    "Content-Security-Policy: default-src 'none'; sandbox allow-scripts allow-downloads; ",
    "script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; ",
    "img-src 'self' data:; font-src 'self' data:; media-src 'self' blob:; connect-src 'self'; ",
    "worker-src 'none'; frame-src 'none'; child-src 'none'; object-src 'none'; ",
    "form-action 'none'; base-uri 'none'; frame-ancestors 'none'; manifest-src 'none'\r\n",
);

struct Request {
    head: bool,
    path: String,
    range: Option<String>,
}

pub(super) async fn serve<S>(
    stream: &mut S,
    bundle: &SiteBundle,
    host: &str,
    deadline: Instant,
    check_live: impl Fn() -> Result<()>,
) -> Result<u64>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    check_live()?;
    let request = timeout_at(
        deadline.min(Instant::now() + Duration::from_secs(5)),
        read_request(stream, host),
    )
    .await
    .context("site request headers timed out")?;
    check_live()?;
    let Ok(request) = request else {
        return empty(stream, "400 Bad Request", "").await;
    };
    let path = if request.path.ends_with('/') {
        format!("{}index.html", request.path)
    } else {
        request.path
    };
    let Some(asset) = bundle.asset(&path) else {
        return empty(stream, "404 Not Found", "").await;
    };
    let length = asset.bytes.len();
    let selected = if request.head {
        // RFC 9110: Range only changes GET semantics, never HEAD.
        Ok(0..length)
    } else {
        request
            .range
            .as_deref()
            .map_or(Ok(0..length), |value| range(value, length))
    };
    let Ok(selected) = selected else {
        return empty(
            stream,
            "416 Range Not Satisfiable",
            &format!("Content-Range: bytes */{length}\r\n"),
        )
        .await;
    };
    let partial = request.range.is_some() && !request.head;
    let status = if partial {
        "206 Partial Content"
    } else {
        "200 OK"
    };
    let content_range = if partial {
        format!(
            "Content-Range: bytes {}-{}/{length}\r\n",
            selected.start,
            selected.end - 1
        )
    } else {
        String::new()
    };
    let headers = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {}\r\nContent-Length: {}\r\nAccept-Ranges: bytes\r\n{content_range}{SECURITY}\r\n",
        asset.content_type,
        selected.len(),
    );
    check_live()?;
    stream.write_all(headers.as_bytes()).await?;
    let mut sent = 0;
    if !request.head {
        for part in asset.bytes[selected].chunks(65536) {
            check_live()?;
            stream.write_all(part).await?;
            sent += u64::try_from(part.len())?;
        }
    }
    check_live()?;
    stream.shutdown().await?;
    Ok(sent)
}

async fn empty<S: AsyncWrite + Unpin>(stream: &mut S, status: &str, extra: &str) -> Result<u64> {
    stream
        .write_all(
            format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\n{extra}{SECURITY}\r\n").as_bytes(),
        )
        .await?;
    stream.shutdown().await?;
    Ok(0)
}

async fn read_request<S: AsyncRead + Unpin>(stream: &mut S, host: &str) -> Result<Request> {
    let mut bytes = [0_u8; MAX_HEADERS];
    let mut used = 0;
    loop {
        let count = stream.read(&mut bytes[used..]).await?;
        if count == 0 {
            bail!("site request ended before complete headers");
        }
        used += count;
        if let Some(request) = parse_request(&bytes[..used], host)? {
            return Ok(request);
        }
        if used == bytes.len() {
            bail!("site request header limit exceeded");
        }
    }
}

fn parse_request(bytes: &[u8], host: &str) -> Result<Option<Request>> {
    let mut fields = [httparse::EMPTY_HEADER; 32];
    let mut request = httparse::Request::new(&mut fields);
    let httparse::Status::Complete(length) = request.parse(bytes)? else {
        return Ok(None);
    };
    if length != bytes.len()
        || request.version != Some(1)
        || !matches!(request.method, Some("GET" | "HEAD"))
    {
        bail!("unsupported site request or body");
    }
    let mut hosts = 0;
    let mut content_lengths = 0;
    let mut range = None;
    for header in request.headers {
        if header.name.eq_ignore_ascii_case("host") {
            hosts += 1;
            if header.value != host.as_bytes() {
                bail!("site host mismatch");
            }
        } else if header.name.eq_ignore_ascii_case("range") {
            if range.is_some() || header.value.len() > 64 {
                bail!("duplicate or oversized site range");
            }
            range = Some(std::str::from_utf8(header.value)?.to_owned());
        } else if header.name.eq_ignore_ascii_case("content-length") {
            content_lengths += 1;
            if content_lengths > 1 || header.value != b"0" {
                bail!("site request bodies are unsupported");
            }
        } else if [
            "transfer-encoding",
            "authorization",
            "proxy-authorization",
            "cookie",
            "upgrade",
            "expect",
        ]
        .iter()
        .any(|name| header.name.eq_ignore_ascii_case(name))
        {
            bail!("site credentials or protocol changes are unsupported");
        }
    }
    if hosts != 1 {
        bail!("site requires one exact host");
    }
    Ok(Some(Request {
        head: request.method == Some("HEAD"),
        path: decoded_path(request.path.context("site path absent")?)?,
        range,
    }))
}

fn decoded_path(path: &str) -> Result<String> {
    if !path.starts_with('/') || path.len() > MAX_SITE_PATH_BYTES * 3 || path.contains(['#', '\\'])
    {
        bail!("unsupported site path");
    }
    // Bounded cache-busting parameters have no dynamic meaning for immutable assets.
    let path = path.split_once('?').map_or(path, |(path, _)| path);
    let mut decoded = Vec::with_capacity(path.len());
    let mut bytes = path.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            let high = bytes
                .next()
                .and_then(|value| char::from(value).to_digit(16));
            let low = bytes
                .next()
                .and_then(|value| char::from(value).to_digit(16));
            let value = u8::try_from(
                high.context("invalid site escape")? * 16 + low.context("invalid site escape")?,
            )?;
            // UTF-8 names are usable, but encoded slash/dot/ASCII aliases never bypass codec rules.
            if value.is_ascii() {
                bail!("encoded ASCII site paths are unsupported");
            }
            decoded.push(value);
        } else {
            decoded.push(byte);
        }
    }
    Ok(String::from_utf8(decoded)?)
}

fn range(value: &str, length: usize) -> Result<Range<usize>> {
    let value = value
        .strip_prefix("bytes=")
        .context("unsupported range unit")?;
    let (first, last) = value.split_once('-').context("invalid byte range")?;
    let number = |value: &str| -> Result<usize> {
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            bail!("invalid byte position");
        }
        Ok(value.parse()?)
    };
    if length == 0 {
        bail!("empty resource has no satisfiable range");
    }
    if first.is_empty() {
        let count = number(last)?;
        if count == 0 {
            bail!("empty suffix range");
        }
        return Ok(length.saturating_sub(count)..length);
    }
    let start = number(first)?;
    let end = if last.is_empty() {
        length
    } else {
        number(last)?.saturating_add(1).min(length)
    };
    if start >= end {
        bail!("unsatisfiable byte range");
    }
    Ok(start..end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use volparossa_content::site::SiteAsset;

    const HOST: &str = "vp00112233445566778899aabbccddeeff.localhost:12345";

    fn bundle() -> SiteBundle {
        SiteBundle::decode(
            SiteBundle::encode(vec![
                SiteAsset {
                    path: "/index.html".into(),
                    content_type: "text/html".into(),
                    bytes: b"<script src='/app.js'></script>".to_vec(),
                },
                SiteAsset {
                    path: "/app.js".into(),
                    content_type: "text/javascript".into(),
                    bytes: b"console.log('static');".to_vec(),
                },
                SiteAsset {
                    path: "/docs/index.html".into(),
                    content_type: "text/html".into(),
                    bytes: b"documentation".to_vec(),
                },
                SiteAsset {
                    path: "/clip.webm".into(),
                    content_type: "video/webm".into(),
                    bytes: b"0123456789".to_vec(),
                },
                SiteAsset {
                    path: "/café.html".into(),
                    content_type: "text/html".into(),
                    bytes: b"UTF-8 name".to_vec(),
                },
            ])
            .expect("encode"),
        )
        .expect("decode")
    }

    async fn exchange(request: String, live: bool) -> (Result<u64>, Vec<u8>) {
        let bundle = bundle();
        let (mut client, mut server) = tokio::io::duplex(32768);
        let (result, bytes) = tokio::join!(
            serve(
                &mut server,
                &bundle,
                HOST,
                Instant::now() + Duration::from_secs(2),
                || {
                    if live {
                        Ok(())
                    } else {
                        bail!("authority expired")
                    }
                }
            ),
            async {
                client.write_all(request.as_bytes()).await.expect("request");
                // Expiry rejects before any output and leaves connection closure to its owner.
                if !live {
                    return Vec::new();
                }
                let mut bytes = Vec::new();
                client.read_to_end(&mut bytes).await.expect("response");
                bytes
            },
        );
        (result, bytes)
    }

    fn request(method: &str, path: &str, headers: &str) -> String {
        format!("{method} {path} HTTP/1.1\r\nHost: {HOST}\r\n{headers}\r\n")
    }

    #[tokio::test]
    async fn immutable_site_http_delivers_assets_directories_head_and_single_media_ranges() {
        for (method, path, extra, status, body) in [
            ("GET", "/", "", "200 OK", "<script src='/app.js'></script>"),
            (
                "GET",
                "/app.js",
                "Origin: null\r\n",
                "200 OK",
                "console.log('static');",
            ),
            ("GET", "/app.js?v=1", "", "200 OK", "console.log('static');"),
            ("GET", "/caf%C3%A9.html", "", "200 OK", "UTF-8 name"),
            ("GET", "/docs/", "", "200 OK", "documentation"),
            ("HEAD", "/clip.webm", "Range: bytes=2-4\r\n", "200 OK", ""),
            (
                "GET",
                "/clip.webm",
                "Range: bytes=2-4\r\n",
                "206 Partial Content",
                "234",
            ),
            (
                "GET",
                "/clip.webm",
                "Range: bytes=-3\r\n",
                "206 Partial Content",
                "789",
            ),
            (
                "GET",
                "/clip.webm",
                "Range: bytes=7-\r\n",
                "206 Partial Content",
                "789",
            ),
            (
                "GET",
                "/clip.webm",
                "Range: bytes=10-\r\n",
                "416 Range Not Satisfiable",
                "",
            ),
        ] {
            let (result, bytes) = exchange(request(method, path, extra), true).await;
            assert_eq!(
                result.expect("served"),
                u64::try_from(body.len()).expect("length")
            );
            let response = String::from_utf8(bytes).expect("UTF-8 fixture");
            assert!(
                response.starts_with(&format!("HTTP/1.1 {status}\r\n")),
                "{response}"
            );
            let (headers, actual) = response.split_once("\r\n\r\n").expect("headers");
            assert_eq!(actual, body);
            assert!(headers.contains("Cache-Control: no-store"));
            assert!(headers.contains("sandbox allow-scripts allow-downloads"));
            assert!(!headers.contains("allow-same-origin"));
            assert!(headers.contains("Access-Control-Allow-Origin: *"));
            assert!(!headers.contains("Allow-Credentials"));
            if method == "HEAD" {
                assert!(headers.contains("Content-Length: 10\r\n"));
            }
        }
    }

    #[tokio::test]
    async fn site_http_rejects_foreign_hosts_credentials_bodies_aliases_and_expired_authority() {
        let mut requests = vec![
            request("GET", "/", "").replace(HOST, "localhost:12345"),
            request("GET", "/", "Cookie: session=bad\r\n"),
            request("GET", "/", "Content-Length: 1\r\n"),
            request("GET", "/", "Transfer-Encoding: chunked\r\n"),
            request("GET", "/%2e%2e/index.html", ""),
            request("GET", "/a%2fb", ""),
            request("POST", "/", ""),
        ];
        requests.push(format!("{}body", request("GET", "/", "")));
        for request in requests {
            let (result, bytes) = exchange(request, true).await;
            assert_eq!(result.expect("bounded rejection"), 0);
            assert!(bytes.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));
            assert!(bytes.ends_with(b"\r\n\r\n"));
        }
        for path in ["/../index.html", "/.secret", "/missing", "//index.html"] {
            let (_, bytes) = exchange(request("GET", path, ""), true).await;
            assert!(bytes.starts_with(b"HTTP/1.1 404 Not Found\r\n"));
        }
        let (result, bytes) = exchange(request("GET", "/", ""), false).await;
        assert!(result.is_err());
        assert!(bytes.is_empty());
    }
}
