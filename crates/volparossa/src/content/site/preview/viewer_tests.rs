// SPDX-License-Identifier: GPL-3.0-only
//! In-memory HTTP exercises the actual shared handler; hosted browser/TCP proof is separate.
use std::{fs, os::unix::fs::PermissionsExt, sync::atomic::AtomicBool};

use clap::Parser as _;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, duplex};
use volparossa_content::{
    CacheLimits, ChunkStore, Metadata, Publication, Validity, publish, site::SiteAsset,
};

use super::*;

fn local_site() -> Site {
    let root = tempfile::tempdir().unwrap();
    let bytes = SiteBundle::encode(vec![SiteAsset {
        path: "/index.html".into(),
        content_type: "text/html".into(),
        bytes: b"<h1>Public fixture</h1>".to_vec(),
    }])
    .unwrap();
    let signer = SigningKey::from_bytes(&[23; 32]);
    let now = now_seconds().unwrap();
    let mut cache = ChunkStore::create(
        &root.path().join("signing-fixture"),
        CacheLimits {
            max_bytes: 1024,
            max_entries: 4,
            min_free_bytes: 0,
        },
    )
    .unwrap();
    let publication = publish(
        &mut bytes.as_slice(),
        Publication {
            length: u64::try_from(bytes.len()).unwrap(),
            metadata: Metadata {
                name: "public-fixture".into(),
                revision: 1,
                content_type: SITE_CONTENT_TYPE.into(),
            },
            validity: Validity {
                created: now - 1,
                expires: now + 600,
            },
        },
        &signer,
        &mut cache,
    )
    .unwrap();
    drop(cache);
    let input = root.path().join("input.vps");
    let manifest = root.path().join("manifest.pb");
    fs::write(&input, &bytes).unwrap();
    fs::write(&manifest, publication.encode()).unwrap();
    for file in [&input, &manifest] {
        fs::set_permissions(file, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let args = crate::Cli::try_parse_from(vec![
        "volparossa".into(),
        "content".into(),
        "site".into(),
        "preview".into(),
        "--input".into(),
        input.into_os_string(),
        "--manifest".into(),
        manifest.into_os_string(),
        "--publisher-key".into(),
        hex::encode(signer.verifying_key().as_bytes()).into(),
        "--expected-input-sha256".into(),
        hex::encode(Sha256::digest(&bytes)).into(),
    ])
    .unwrap();
    let crate::CliCommand::Content { command } = args.command else {
        panic!("content expected")
    };
    let crate::content::Command::Site(super::super::Command::Preview(args)) = *command else {
        panic!("preview expected")
    };
    let prepared = super::super::preview::prepare_blocking(
        &args,
        Instant::now(),
        now,
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap();
    Site {
        source: Source::LocalSigned(Box::new(prepared.authority)),
        bundle: prepared.bundle,
        deadline: prepared.deadline,
        expires: prepared.expires,
        host: "vp-public-fixture.localhost:12345".into(),
    }
}

async fn exchange(site: Site, request: &[u8]) -> Vec<u8> {
    let (mut client, mut server) = duplex(16 * 1024);
    let deadline = site.deadline;
    let server = tokio::spawn(async move {
        http::serve(&mut server, &site.bundle, &site.host, deadline, || {
            site.check_live()
        })
        .await
    });
    client.write_all(request).await.unwrap();
    let mut response = Vec::new();
    timeout_at(
        Instant::now() + Duration::from_secs(2),
        client.read_to_end(&mut response),
    )
    .await
    .unwrap()
    .unwrap();
    server.await.unwrap().unwrap();
    response
}

#[tokio::test]
async fn local_source_uses_existing_http_csp_exact_host_path_and_method_gates() {
    let response = exchange(
        local_site(),
        b"GET / HTTP/1.1\r\nHost: vp-public-fixture.localhost:12345\r\n\r\n",
    )
    .await;
    let text = std::str::from_utf8(&response).unwrap();
    assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(text.ends_with("<h1>Public fixture</h1>"));
    for security in [
        "Cache-Control: no-store",
        "X-Content-Type-Options: nosniff",
        "sandbox allow-scripts allow-downloads",
        "worker-src 'none'",
        "frame-src 'none'",
        "form-action 'none'",
        "Connection: close",
    ] {
        assert!(text.contains(security));
    }
    for request in [
        b"GET / HTTP/1.1\r\nHost: wrong.localhost:12345\r\n\r\n".as_slice(),
        b"POST / HTTP/1.1\r\nHost: vp-public-fixture.localhost:12345\r\n\r\n",
        b"GET /%2e%2e/private HTTP/1.1\r\nHost: vp-public-fixture.localhost:12345\r\n\r\n",
    ] {
        let response = exchange(local_site(), request).await;
        assert!(response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));
        assert!(
            !response
                .windows(b"<h1>Public fixture</h1>".len())
                .any(|part| part == b"<h1>Public fixture</h1>")
        );
    }
}

#[tokio::test]
async fn local_source_original_expiry_and_monotonic_expiry_close_without_asset_bytes() {
    for wall_expiry in [false, true] {
        let mut site = local_site();
        if wall_expiry {
            site.expires = now_seconds().unwrap();
        } else {
            site.deadline = Instant::now();
        }
        let (mut client, mut stream) = duplex(1024);
        assert!(
            http::serve(&mut stream, &site.bundle, &site.host, site.deadline, || {
                site.check_live()
            })
            .await
            .is_err()
        );
        drop(stream);
        let mut bytes = Vec::new();
        client.read_to_end(&mut bytes).await.unwrap();
        assert!(bytes.is_empty());
    }
}

#[test]
fn local_report_never_inherits_named_receipts_or_a_fake_private_spool() {
    let site = local_site();
    let report = site.report();
    assert_eq!(
        site.source.operations(),
        ("local_site_preview_ready", "local_site_preview_closed")
    );
    assert_eq!(report["source"], "local_signed_bundle");
    assert_eq!(report["native_publisher_authenticated"], true);
    assert_eq!(report["publisher_signature_verified"], true);
    assert_eq!(report["reviewed_input_sha256_matched"], true);
    for absent in [
        "providers_used",
        "peer_bytes",
        "cache_only",
        "private_spool_removed",
        "provider_peer_ids",
        "control_relay_peer_id",
    ] {
        assert!(report.get(absent).is_none());
    }
}
