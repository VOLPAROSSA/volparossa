//! Provider application TLS inside the normal Client/Relay/Exit protected stream.
//!
//! Reuse libp2p's TLS 1.3 certificate identity proof, pinned to the independently verified
//! service offer. The client uses a fresh per-session identity: its permanent node identity is
//! never disclosed to a content destination. Neither certificate nor offer authenticates an
//! Internet origin, publication or whitelist grant. Those authorities remain independent.

use std::{sync::Arc, time::Duration};

use libp2p::{PeerId, identity};
use rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use rustls_pki_types::ServerName;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::timeout,
};
use tokio_rustls::{
    TlsAcceptor, TlsConnector, client::TlsStream as ClientStream, server::TlsStream as ServerStream,
};
use volparossa_content::provider::VerifiedProviderOffer;

const CONTENT_ALPN: &[u8] = b"volparossa-content/1";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const CLOSE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, thiserror::Error)]
pub(super) enum ContentTlsError {
    #[error("content TLS offer identity or lifetime is invalid")]
    Offer,
    #[error("content TLS configuration is unavailable")]
    Configuration,
    #[error("content TLS authenticated handshake failed")]
    Handshake,
    #[error("content TLS clean shutdown failed")]
    Close,
}

#[derive(Debug)]
struct NamedCertificate {
    hostname: String,
    inner: Arc<dyn ResolvesServerCert>,
}

impl ResolvesServerCert for NamedCertificate {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if hello.server_name() != Some(self.hostname.as_str()) {
            return None;
        }
        self.inner.resolve(hello)
    }
}

#[derive(Clone)]
pub(super) struct ContentTlsServer {
    acceptor: TlsAcceptor,
}

impl ContentTlsServer {
    pub(super) fn new(
        identity: &identity::Keypair,
        hostname: &str,
    ) -> Result<Self, ContentTlsError> {
        let mut config = libp2p::tls::make_server_config(identity)
            .map_err(|_| ContentTlsError::Configuration)?;
        config.cert_resolver = Arc::new(NamedCertificate {
            hostname: hostname.to_owned(),
            inner: Arc::clone(&config.cert_resolver),
        });
        config.alpn_protocols = vec![CONTENT_ALPN.to_vec()];
        Ok(Self {
            acceptor: TlsAcceptor::from(Arc::new(config)),
        })
    }

    pub(super) async fn accept<S>(&self, stream: S) -> Result<ServerStream<S>, ContentTlsError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let tls = timeout(HANDSHAKE_TIMEOUT, self.acceptor.accept(stream))
            .await
            .map_err(|_| ContentTlsError::Handshake)?
            .map_err(|_| ContentTlsError::Handshake)?;
        if tls.get_ref().1.alpn_protocol() != Some(CONTENT_ALPN)
            || tls.get_ref().1.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
        {
            return Err(ContentTlsError::Handshake);
        }
        Ok(tls)
    }
}

/// The supplied stream must already use the normal authorized MPTCP/Exit route.
pub(super) async fn connect<S>(
    stream: S,
    peer: PeerId,
    offer: &VerifiedProviderOffer,
) -> Result<ClientStream<S>, ContentTlsError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    validate_offer(peer, offer)?;
    // libp2p TLS requires mutual authentication. A one-session key avoids turning a cache
    // request into a durable Client-node-to-publication association at the provider.
    let ephemeral = identity::Keypair::generate_ed25519();
    let mut config = libp2p::tls::make_client_config(&ephemeral, Some(peer))
        .map_err(|_| ContentTlsError::Configuration)?;
    config.alpn_protocols = vec![CONTENT_ALPN.to_vec()];
    config.enable_sni = true;
    let hostname = ServerName::try_from(offer.endpoint().hostname().to_owned())
        .map_err(|_| ContentTlsError::Offer)?;
    let connector = TlsConnector::from(Arc::new(config));
    let tls = timeout(HANDSHAKE_TIMEOUT, connector.connect(hostname, stream))
        .await
        .map_err(|_| ContentTlsError::Handshake)?
        .map_err(|_| ContentTlsError::Handshake)?;
    validate_offer(peer, offer)?;
    if tls.get_ref().1.alpn_protocol() != Some(CONTENT_ALPN)
        || tls.get_ref().1.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
    {
        return Err(ContentTlsError::Handshake);
    }
    Ok(tls)
}

fn validate_offer(peer: PeerId, offer: &VerifiedProviderOffer) -> Result<(), ContentTlsError> {
    let key = identity::ed25519::PublicKey::try_from_bytes(offer.provider_key())
        .map_err(|_| ContentTlsError::Offer)?;
    let expected = identity::PublicKey::from(key).to_peer_id();
    let now = super::now();
    if peer != expected || now < offer.validity().created || now >= offer.validity().expires {
        return Err(ContentTlsError::Offer);
    }
    Ok(())
}

/// Half-close TLS and require the peer's clean EOF before dropping the underlying transport.
/// Nested application TLS also half-closes the outer TLS write side; callers subsequently
/// finish that outer stream to consume its own `close_notify`, rather than turning success into
/// an aborted MPTCP proxy flow. Trailing application bytes or abrupt EOF are never accepted.
pub(super) async fn finish<S>(stream: &mut S) -> Result<(), ContentTlsError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    timeout(CLOSE_TIMEOUT, async {
        stream
            .shutdown()
            .await
            .map_err(|_| ContentTlsError::Close)?;
        let count = stream
            .read(&mut [0_u8; 1])
            .await
            .map_err(|_| ContentTlsError::Close)?;
        if count != 0 {
            return Err(ContentTlsError::Close);
        }
        Ok(())
    })
    .await
    .map_err(|_| ContentTlsError::Close)?
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
    use volparossa_content::{
        CacheLimits, ChunkStore, Metadata, Publication, Validity,
        provider::{
            ProviderEndpoint, PublicationRegistry, SignedProviderOffer, pull_publication,
            serve_publication,
        },
        transfer::TransferLimits,
    };
    use zeroize::Zeroizing;

    const HOSTNAME: &str = "provider-a.volparossa.test";

    fn offer(key: &identity::Keypair, hostname: &str) -> VerifiedProviderOffer {
        let pair = key.clone().try_into_ed25519().unwrap();
        let bytes = Zeroizing::new(pair.to_bytes());
        let signer = SigningKey::from_keypair_bytes(&bytes).unwrap();
        let now = super::super::now();
        SignedProviderOffer::sign(
            &signer,
            ProviderEndpoint::new(hostname, 18080).unwrap(),
            Validity {
                created: now,
                expires: now + 300,
            },
        )
        .unwrap()
        .verify(&signer.verifying_key(), now)
        .unwrap()
    }

    #[tokio::test]
    async fn provider_tls_transfers_exact_registered_chunks_with_independent_publisher() {
        let provider = identity::Keypair::generate_ed25519();
        let peer = provider.public().to_peer_id();
        let offer = offer(&provider, HOSTNAME);
        let tls = ContentTlsServer::new(&provider, HOSTNAME).unwrap();
        let root = tempfile::tempdir().unwrap();
        let limits = CacheLimits {
            max_bytes: 4 * volparossa_content::CHUNK_BYTES as u64,
            max_entries: 16,
            min_free_bytes: 0,
        };
        let path = root.path().join("provider");
        let mut cache = ChunkStore::create(&path, limits).unwrap();
        let publisher = SigningKey::generate(&mut rand_core::OsRng);
        let bytes = vec![0x37; volparossa_content::CHUNK_BYTES + 123];
        let now = super::super::now();
        let manifest = volparossa_content::publish(
            &mut bytes.as_slice(),
            Publication {
                metadata: Metadata {
                    name: "explicit-native-content".into(),
                    revision: 1,
                    content_type: "application/octet-stream".into(),
                },
                length: bytes.len() as u64,
                validity: Validity {
                    created: now - 1,
                    expires: now + 300,
                },
            },
            &publisher,
            &mut cache,
        )
        .unwrap()
        .verify(&publisher.verifying_key(), now)
        .unwrap();
        drop(cache);
        let mut registry = PublicationRegistry::new();
        registry
            .register(manifest.clone(), path, limits, now)
            .unwrap();
        let mut consumer = ChunkStore::create(&root.path().join("consumer"), limits).unwrap();
        let (client, server) = duplex(4096);
        let (received, sent) = tokio::join!(
            async {
                let mut stream = connect(client, peer, &offer).await.unwrap();
                let progress = pull_publication(
                    &mut stream,
                    &manifest,
                    &mut consumer,
                    TransferLimits::default(),
                )
                .await
                .unwrap();
                finish(&mut stream).await.unwrap();
                progress
            },
            async {
                let mut stream = tls.accept(server).await.unwrap();
                let progress = serve_publication(&mut stream, &registry, TransferLimits::default())
                    .await
                    .unwrap();
                finish(&mut stream).await.unwrap();
                progress
            },
        );
        assert_eq!(received, sent);
        assert_eq!(received.bytes, bytes.len() as u64);
        assert_eq!(received.chunks, 2);
        let mut output = Vec::new();
        volparossa_content::reassemble(&manifest, &mut [&mut consumer], now, &mut output).unwrap();
        assert_eq!(output, bytes);
    }

    #[tokio::test]
    async fn provider_tls_rejects_wrong_server_peer_pin_and_wrong_signed_sni() {
        let expected = identity::Keypair::generate_ed25519();
        let wrong = identity::Keypair::generate_ed25519();
        let peer = expected.public().to_peer_id();
        for (server_key, advertised) in [
            (&wrong, HOSTNAME),
            (&expected, "provider-b.volparossa.test"),
        ] {
            let tls = ContentTlsServer::new(server_key, HOSTNAME).unwrap();
            let offer = offer(&expected, advertised);
            let (client, server) = duplex(4096);
            let (client, server) = tokio::join!(connect(client, peer, &offer), tls.accept(server));
            assert!(
                client.is_err(),
                "identity mismatch or SNI mismatch must abort real TLS"
            );
            assert!(server.is_err());
        }
        let offer = offer(&expected, HOSTNAME);
        let (client, mut server) = duplex(4096);
        assert!(
            connect(client, wrong.public().to_peer_id(), &offer)
                .await
                .is_err()
        );
        assert_eq!(
            server.read(&mut [0_u8; 1]).await.unwrap(),
            0,
            "offer/expected-peer mismatch sends no ClientHello"
        );
    }

    #[tokio::test]
    async fn provider_tls_has_visible_policy_sni_and_fresh_client_identity_each_session() {
        let provider = identity::Keypair::generate_ed25519();
        let peer = provider.public().to_peer_id();
        let offer = offer(&provider, HOSTNAME);
        let tls = ContentTlsServer::new(&provider, HOSTNAME).unwrap();
        let mut clients = Vec::new();
        for _ in 0..2 {
            let exit = identity::Keypair::generate_ed25519();
            let exit_peer = exit.public().to_peer_id();
            let exit_offer = self::offer(&exit, HOSTNAME);
            let exit_tls = ContentTlsServer::new(&exit, HOSTNAME).unwrap();
            let (client, observed) = duplex(4096);
            let (mut forwarded, server) = duplex(4096);
            let ((), authenticated_client, ()) = tokio::join!(
                async {
                    let mut outer = connect(client, exit_peer, &exit_offer).await.unwrap();
                    let mut stream = connect(&mut outer, peer, &offer).await.unwrap();
                    stream.write_all(b"x").await.unwrap();
                    assert_eq!(stream.read_u8().await.unwrap(), b'y');
                    finish(&mut stream).await.unwrap();
                    drop(stream);
                    finish(&mut outer).await.unwrap();
                },
                async {
                    let mut stream = tls.accept(server).await.unwrap();
                    let certificate = &stream.get_ref().1.peer_certificates().unwrap()[0];
                    let client = libp2p::tls::certificate::parse(certificate)
                        .unwrap()
                        .peer_id();
                    assert_eq!(stream.read_u8().await.unwrap(), b'x');
                    stream.write_all(b"y").await.unwrap();
                    finish(&mut stream).await.unwrap();
                    client
                },
                async {
                    let mut observed = exit_tls.accept(observed).await.unwrap();
                    let mut record = [0_u8; 5];
                    observed.read_exact(&mut record).await.unwrap();
                    assert_eq!(record[0], 0x16, "actual ClientHello, not selector framing");
                    let length = usize::from(u16::from_be_bytes([record[3], record[4]]));
                    assert!(length <= 16 * 1024);
                    let mut hello = vec![0; length + record.len()];
                    hello[..5].copy_from_slice(&record);
                    observed.read_exact(&mut hello[5..]).await.unwrap();
                    volparossa_exit::inspect_tls_client_hello(&hello, HOSTNAME).unwrap();
                    assert!(
                        volparossa_exit::inspect_tls_client_hello(
                            &hello,
                            "provider-b.volparossa.test"
                        )
                        .is_err()
                    );
                    forwarded.write_all(&hello).await.unwrap();
                    let stats = volparossa_tcp_proxy::proxy_bidirectional(
                        &mut observed,
                        &mut forwarded,
                        volparossa_tcp_proxy::StreamTransferLimits::new(
                            4096,
                            64 * 1024,
                            64 * 1024,
                            Duration::from_secs(10),
                        )
                        .unwrap(),
                    )
                    .await
                    .unwrap();
                    assert!(stats.client_to_exit_bytes > 0);
                    assert!(stats.exit_to_client_bytes > 0);
                },
            );
            assert_ne!(authenticated_client, peer);
            assert!(!clients.contains(&authenticated_client));
            clients.push(authenticated_client);
        }
    }
}
