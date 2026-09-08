//! Explicit cooperative-origin HTTPS retrieval over the existing protected content streams.
//!
//! Origin trust is authenticated before any provider lookup, and remains in memory until
//! atomic output reconstruction. Cached native signatures never substitute for HTTPS authority.

use std::{path::PathBuf, time::Duration};

use rustls::RootCertStore;
use rustls_pki_types::{CertificateDer, pem::PemObject};
use tokio::io::AsyncReadExt;
use tokio::{net::UnixStream, time::timeout};
use volparossa_content::ChunkStore;
use volparossa_content::origin_https::{
    OriginAuthorizedManifest, OriginClient, OriginLimits, OriginRequest,
};
use volparossa_content::transfer::{TransferLimits, serve_peer};
use volparossa_local_control::{
    CONTROL_PROTOCOL_VERSION, ContentReceipt, ControlResponse, ControlResult,
    HttpsContentFetchRequest, HttpsContentTransferReady, control_response::Payload, write_response,
};
use volparossa_policy::{TransportProtocol, VerifiedManifest as VerifiedPolicy};

use super::{ContentError, ContentRuntime, download_cache, limits, now};
use crate::{
    control::ControlContext, mptcp_flow_runtime::ActiveProductionMptcpClientFlow, unix_millis,
};

const MAX_EXPLICIT_CA_BYTES: usize = 128 * 1024;
const MAX_SYSTEM_CA_BYTES: usize = 1024 * 1024;
const MAX_ROOTS: usize = 512;
const SYSTEM_CA_BUNDLE: &str = "/etc/ssl/certs/ca-certificates.crt";

pub(super) async fn fetch(
    request: HttpsContentFetchRequest,
    context: &ControlContext,
) -> Result<ContentReceipt, ContentError> {
    let output = PathBuf::from(&request.output);
    if output.try_exists().map_err(|_| ContentError::Invalid)? {
        return Err(ContentError::Invalid);
    }
    let mut download = retrieve(request, context).await?;
    download.receipt.bytes = download
        .authorized
        .reassemble_to_file(&mut [&mut download.store], now(), &output)
        .map_err(|_| ContentError::Unavailable)?;
    Ok(download.receipt)
}

struct PreparedDownload {
    origin: OriginRequest,
    policy: VerifiedPolicy,
    authorized: OriginAuthorizedManifest,
    store: ChunkStore,
    receipt: ContentReceipt,
}

async fn retrieve(
    request: HttpsContentFetchRequest,
    context: &ControlContext,
) -> Result<PreparedDownload, ContentError> {
    let origin = OriginRequest::new(&request.resource_url, &request.metadata_path)
        .map_err(|_| ContentError::Invalid)?;
    let client = OriginClient::new(
        load_roots(&request.ca_certificates_pem).await?,
        OriginLimits::default(),
    )
    .map_err(|_| ContentError::Invalid)?;
    let cache_limits = limits(request.limits)?;
    let policy = {
        let state = context.state.read().await;
        if !state.roles().client {
            return Err(ContentError::Policy);
        }
        state
            .active_policy(unix_millis())
            .ok_or(ContentError::Policy)?
    };
    checked_policy(context, &origin, &policy).await?;
    Box::pin(
        context
            .routes
            .connect_tcp(&context.config, &context.discovery, &context.helper),
    )
    .await
    .map_err(|_| ContentError::Unavailable)?;
    let control_peer = context
        .routes
        .content_discovery_control()
        .await
        .ok_or(ContentError::Unavailable)?;
    let mut flow = open_origin_stream(context, &origin, &policy).await?;
    let authenticated = client
        .authenticate_manifest(flow.stream_mut(), &origin, now())
        .await;
    if authenticated.is_ok() && super::tls::finish(flow.stream_mut()).await.is_err() {
        super::content_event(context, "CONTENT_ORIGIN_ROUTE_CLOSE_FAILED").await;
        return Err(ContentError::Unavailable);
    }
    flow.shutdown();
    let authorized = authenticated.map_err(|_| ContentError::Unavailable)?;
    let mut store = download_cache(&request.cache, cache_limits, request.reuse_cache)?;
    // Check full-object cache capacity and HTTPS freshness before contacting any peers.
    authorized
        .next_missing_range(&mut store, now())
        .map_err(|_| ContentError::Invalid)?;
    let (providers, peer_bytes) = match ContentRuntime::pull_registered_providers(
        context,
        authorized.manifest(),
        &mut store,
        &policy,
        control_peer,
    )
    .await
    {
        Ok(providers) => providers,
        Err(ContentError::Unavailable) => (Vec::new(), 0),
        Err(error) => return Err(error),
    };
    let (origin_body_bytes, origin_range_requests) =
        fill_missing(context, &client, &origin, &authorized, &policy, &mut store).await?;
    checked_policy(context, &origin, &policy).await?;
    let receipt = ContentReceipt {
        bytes: authorized.manifest().length(),
        chunks: u32::try_from(authorized.manifest().chunks().len())
            .map_err(|_| ContentError::Invalid)?,
        providers_used: u32::try_from(providers.len()).map_err(|_| ContentError::Invalid)?,
        provider_peer_ids: providers,
        control_relay_peer_id: control_peer.to_string(),
        origin_authenticated: true,
        origin_body_bytes,
        peer_bytes,
        origin_range_requests,
        ..ContentReceipt::default()
    };
    Ok(PreparedDownload {
        origin,
        policy,
        authorized,
        store,
        receipt,
    })
}

/// Complete fresh origin authorization and deliver directly from the owned cache.
/// `ready_sent` prevents a later error from being injected into unfinished chunk framing.
pub(super) async fn download(
    request: HttpsContentFetchRequest,
    context: &ControlContext,
    stream: &mut UnixStream,
    request_id: &[u8],
    ready_sent: &mut bool,
) -> Result<(), ContentError> {
    if !request.output.is_empty() {
        return Err(ContentError::Invalid);
    }
    let resource_url = request.resource_url.clone();
    let mut download = retrieve(request, context).await?;
    download.receipt.bytes = download
        .authorized
        .verify_cached(&mut download.store, now())
        .map_err(|_| ContentError::Unavailable)?;
    let expires = download
        .authorized
        .check_validity(now())
        .map_err(|_| ContentError::Unavailable)?;
    let remaining = expires
        .checked_sub(now())
        .filter(|seconds| *seconds > 0)
        .ok_or(ContentError::Unavailable)?;
    timeout(Duration::from_secs(remaining.min(30)), async {
        let ready = HttpsContentTransferReady {
            manifest: download.authorized.native_manifest_bytes().to_vec(),
            publisher_key: download.authorized.manifest().publisher().to_vec(),
            resource_url,
            expires_unix_seconds: expires,
        };
        checked_policy(context, &download.origin, &download.policy).await?;
        *ready_sent = true;
        send_local_response(
            stream,
            request_id,
            "HTTPS_CONTENT_TRANSFER_READY",
            Payload::HttpsContentTransferReady(ready),
        )
        .await?;
        let manifest = download.authorized.manifest();
        let progress = serve_peer(
            stream,
            manifest,
            &mut download.store,
            TransferLimits {
                exchange_timeout: Duration::from_secs(5),
                session_timeout: Duration::from_secs(30),
                max_requests: manifest.chunks().len().max(1),
                max_bytes: manifest.length().max(1),
            },
        )
        .await
        .map_err(|_| ContentError::Unavailable)?;
        if progress.missing != 0
            || progress.bytes != manifest.length()
            || progress.chunks != manifest.chunks().len()
        {
            return Err(ContentError::Unavailable);
        }
        download
            .authorized
            .check_validity(now())
            .map_err(|_| ContentError::Unavailable)?;
        checked_policy(context, &download.origin, &download.policy).await?;
        send_local_response(
            stream,
            request_id,
            "CONTENT_OK",
            Payload::Content(download.receipt),
        )
        .await
    })
    .await
    .map_err(|_| ContentError::Unavailable)?
}

async fn send_local_response(
    stream: &mut UnixStream,
    request_id: &[u8],
    code: &str,
    payload: Payload,
) -> Result<(), ContentError> {
    write_response(
        stream,
        &ControlResponse {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            request_id: request_id.to_vec(),
            result: ControlResult::Ok as i32,
            diagnostic_code: code.into(),
            payload: Some(payload),
        },
    )
    .await
    .map_err(|_| ContentError::Unavailable)
}

async fn checked_policy(
    context: &ControlContext,
    origin: &OriginRequest,
    original: &VerifiedPolicy,
) -> Result<VerifiedPolicy, ContentError> {
    let state = context.state.read().await;
    let current = state
        .active_policy(unix_millis())
        .ok_or(ContentError::Policy)?;
    if !state.roles().client || current.policy_hash() != original.policy_hash() {
        return Err(ContentError::Policy);
    }
    current
        .authorize_domain(
            unix_millis(),
            origin.hostname(),
            TransportProtocol::Tcp,
            origin.port(),
        )
        .map_err(|_| ContentError::Policy)?;
    Ok(current)
}

async fn open_origin_stream(
    context: &ControlContext,
    origin: &OriginRequest,
    policy: &VerifiedPolicy,
) -> Result<ActiveProductionMptcpClientFlow, ContentError> {
    let current = checked_policy(context, origin, policy).await?;
    context
        .routes
        .open_content_stream(&current, origin.hostname(), origin.port(), unix_millis())
        .await
        .map_err(|_| ContentError::Unavailable)
}

async fn fill_missing(
    context: &ControlContext,
    client: &OriginClient,
    origin: &OriginRequest,
    authorized: &OriginAuthorizedManifest,
    policy: &VerifiedPolicy,
    store: &mut ChunkStore,
) -> Result<(u64, u32), ContentError> {
    let mut bytes = 0_u64;
    let mut requests = 0_u32;
    while authorized
        .next_missing_range(store, now())
        .map_err(|_| ContentError::Unavailable)?
        .is_some()
    {
        if requests as usize >= authorized.manifest().chunks().len() {
            return Err(ContentError::Unavailable);
        }
        let mut flow = open_origin_stream(context, origin, policy).await?;
        let progress = client
            .fill_next_missing_from_origin(flow.stream_mut(), authorized, store, now())
            .await;
        if progress.is_ok() && super::tls::finish(flow.stream_mut()).await.is_err() {
            super::content_event(context, "CONTENT_ORIGIN_ROUTE_CLOSE_FAILED").await;
            return Err(ContentError::Unavailable);
        }
        flow.shutdown();
        let progress = progress.map_err(|_| ContentError::Unavailable)?;
        if progress.requested.is_none()
            || progress.chunks_verified == 0
            || progress.bytes_received == 0
        {
            return Err(ContentError::Unavailable);
        }
        requests += 1;
        bytes = bytes
            .checked_add(progress.bytes_received)
            .ok_or(ContentError::Invalid)?;
    }
    Ok((bytes, requests))
}

async fn load_roots(explicit: &[u8]) -> Result<RootCertStore, ContentError> {
    if !explicit.is_empty() {
        return parse_roots(explicit, MAX_EXPLICIT_CA_BYTES);
    }
    let file = tokio::fs::File::open(SYSTEM_CA_BUNDLE)
        .await
        .map_err(|_| ContentError::Unavailable)?;
    let mut bytes = Vec::new();
    file.take(MAX_SYSTEM_CA_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| ContentError::Unavailable)?;
    parse_roots(&bytes, MAX_SYSTEM_CA_BYTES)
}

fn parse_roots(bytes: &[u8], maximum: usize) -> Result<RootCertStore, ContentError> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(ContentError::Invalid);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| ContentError::Invalid)?;
    for line in text.lines().map(str::trim) {
        if (line.contains("-----BEGIN ") && line != "-----BEGIN CERTIFICATE-----")
            || (line.contains("-----END ") && line != "-----END CERTIFICATE-----")
        {
            return Err(ContentError::Invalid);
        }
    }
    let mut roots = RootCertStore::empty();
    for certificate in CertificateDer::pem_slice_iter(bytes) {
        if roots.len() == MAX_ROOTS {
            return Err(ContentError::Invalid);
        }
        roots
            .add(certificate.map_err(|_| ContentError::Invalid)?)
            .map_err(|_| ContentError::Invalid)?;
    }
    if roots.is_empty() {
        return Err(ContentError::Invalid);
    }
    Ok(roots)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_ca_bundle_parses_real_certificates_without_installation() {
        let mut parameters = rcgen::CertificateParams::default();
        parameters.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key = rcgen::KeyPair::generate().expect("CA key");
        let certificate = parameters.self_signed(&key).expect("CA certificate");
        let pem = certificate.pem();
        assert_eq!(
            parse_roots(pem.as_bytes(), MAX_EXPLICIT_CA_BYTES)
                .expect("roots")
                .len(),
            1
        );
        let with_private_key = format!("{pem}{}", key.serialize_pem());
        assert!(parse_roots(with_private_key.as_bytes(), MAX_EXPLICIT_CA_BYTES).is_err());
    }

    #[test]
    fn ca_input_rejects_empty_invalid_der_and_oversized_bundles() {
        for bytes in [
            Vec::new(),
            b"not a PEM certificate".to_vec(),
            b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n".to_vec(),
            vec![b' '; MAX_EXPLICIT_CA_BYTES + 1],
        ] {
            assert!(parse_roots(&bytes, MAX_EXPLICIT_CA_BYTES).is_err());
        }
    }

    #[test]
    fn origin_request_preserves_exact_policy_endpoint_and_same_origin_path() {
        for (url, port) in [
            ("https://origin.example/asset", 443),
            ("https://origin.example:18443/asset", 18443),
        ] {
            let request = OriginRequest::new(url, "/.well-known/content/asset").expect("origin");
            assert_eq!(request.hostname(), "origin.example");
            assert_eq!(request.port(), port);
        }
        for (url, path) in [
            ("http://origin.example/asset", "/metadata"),
            ("https://127.0.0.1/asset", "/metadata"),
            ("https://user@origin.example/asset", "/metadata"),
            ("https://origin.example/asset#fragment", "/metadata"),
            ("https://origin.example/asset", "//other.example/metadata"),
        ] {
            assert!(OriginRequest::new(url, path).is_err());
        }
    }
}
