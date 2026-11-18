use super::*;
use ed25519_dalek::SigningKey;
use tokio::io::{AsyncReadExt, duplex};
use volparossa_content::{
    Validity,
    provider::{ProviderEndpoint, SignedProviderOffer},
};
use zeroize::Zeroizing;

const HOSTNAME: &str = "provider-diagnostic.volparossa.test";

fn offer(identity: &identity::Keypair) -> VerifiedProviderOffer {
    let now = super::super::now();
    offer_at(identity, now)
}

fn offer_at(identity: &identity::Keypair, created: u64) -> VerifiedProviderOffer {
    let pair = identity.clone().try_into_ed25519().unwrap();
    let bytes = Zeroizing::new(pair.to_bytes());
    let signer = SigningKey::from_keypair_bytes(&bytes).unwrap();
    SignedProviderOffer::sign(
        &signer,
        ProviderEndpoint::new(HOSTNAME, 18080).unwrap(),
        Validity {
            created,
            expires: created + 300,
        },
    )
    .unwrap()
    .verify(&signer.verifying_key(), created)
    .unwrap()
}

#[test]
fn typed_tls_errors_are_closed_and_io_timeout_is_not_our_deadline() {
    for (error, expected) in [
        (
            rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ),
            PrivateStorageTlsFailure::Authentication,
        ),
        (
            rustls::Error::NoCertificatesPresented,
            PrivateStorageTlsFailure::Authentication,
        ),
        (
            rustls::Error::NoApplicationProtocol,
            PrivateStorageTlsFailure::TlsOther,
        ),
        (
            rustls::Error::General("private-canary-must-not-be-classified-by-text".into()),
            PrivateStorageTlsFailure::TlsOther,
        ),
    ] {
        assert_eq!(
            handshake_failure(&io::Error::new(io::ErrorKind::InvalidData, error)),
            expected
        );
    }
    for kind in [
        io::ErrorKind::TimedOut,
        io::ErrorKind::UnexpectedEof,
        io::ErrorKind::ConnectionReset,
        io::ErrorKind::InvalidData,
    ] {
        assert_eq!(
            handshake_failure(&io::Error::new(kind, "private-canary-no-error-export")),
            PrivateStorageTlsFailure::Io
        );
    }
}

#[tokio::test]
async fn observed_offer_rejection_preserves_error_and_sends_no_client_hello() {
    let provider = identity::Keypair::generate_ed25519();
    let wrong = identity::Keypair::generate_ed25519();
    let offer = offer(&provider);
    let expired = offer_at(&provider, super::super::now() - 301);
    for (peer, offer) in [
        (wrong.public().to_peer_id(), &offer),
        (provider.public().to_peer_id(), &expired),
    ] {
        let (client, mut server) = duplex(4096);
        assert!(matches!(
            connect_observed(client, peer, offer).await,
            Err((ContentTlsError::Offer, PrivateStorageTlsFailure::Offer))
        ));
        assert_eq!(server.read(&mut [0_u8; 1]).await.unwrap(), 0);
    }
}

#[tokio::test]
async fn nested_tls_wrong_provider_pin_reports_authentication_without_changing_error() {
    let expected = identity::Keypair::generate_ed25519();
    let wrong = identity::Keypair::generate_ed25519();
    let exit = identity::Keypair::generate_ed25519();
    let offer = offer(&expected);
    let exit_offer = self::offer(&exit);
    let provider_tls = ContentTlsServer::new(&wrong, HOSTNAME).unwrap();
    let exit_tls = ContentTlsServer::new(&exit, HOSTNAME).unwrap();
    let (client, protected) = duplex(4096);
    let (mut forwarded, provider) = duplex(4096);
    timeout(Duration::from_secs(20), async {
        let ((), provider_result, _) = tokio::join!(
            async {
                let mut outer = connect(client, exit.public().to_peer_id(), &exit_offer)
                    .await
                    .unwrap();
                assert!(matches!(
                    connect_observed(&mut outer, expected.public().to_peer_id(), &offer).await,
                    Err((
                        ContentTlsError::Handshake,
                        PrivateStorageTlsFailure::Authentication
                    ))
                ));
            },
            provider_tls.accept(provider),
            async {
                let mut outer = exit_tls.accept(protected).await.unwrap();
                tokio::io::copy_bidirectional(&mut outer, &mut forwarded).await
            },
        );
        assert!(provider_result.is_err());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn nested_tls_abrupt_protected_eof_reports_io_not_provider_authentication() {
    let provider = identity::Keypair::generate_ed25519();
    let exit = identity::Keypair::generate_ed25519();
    let offer = offer(&provider);
    let exit_offer = self::offer(&exit);
    let exit_tls = ContentTlsServer::new(&exit, HOSTNAME).unwrap();
    let (client, protected) = duplex(4096);
    timeout(Duration::from_secs(20), async {
        let ((), ()) = tokio::join!(
            async {
                let mut outer = connect(client, exit.public().to_peer_id(), &exit_offer)
                    .await
                    .unwrap();
                assert!(matches!(
                    connect_observed(&mut outer, provider.public().to_peer_id(), &offer).await,
                    Err((ContentTlsError::Handshake, PrivateStorageTlsFailure::Io))
                ));
            },
            async {
                let mut outer = exit_tls.accept(protected).await.unwrap();
                // Consume actual inner ClientHello bytes before the carrying stream
                // disappears; this is not a provider-authentication observation.
                assert_eq!(outer.read_u8().await.unwrap(), 0x16);
            },
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn actual_ten_second_handshake_deadline_is_distinct_from_io_and_drops_stream() {
    assert_eq!(HANDSHAKE_TIMEOUT, Duration::from_secs(10));
    let provider = identity::Keypair::generate_ed25519();
    let offer = offer(&provider);
    let (client, mut silent_server) = duplex(4096);
    let started = tokio::time::Instant::now();
    let result = timeout(
        Duration::from_secs(20),
        connect_observed(client, provider.public().to_peer_id(), &offer),
    )
    .await
    .unwrap();
    assert!(matches!(
        result,
        Err((
            ContentTlsError::Handshake,
            PrivateStorageTlsFailure::HandshakeDeadline
        ))
    ));
    assert!(started.elapsed() >= HANDSHAKE_TIMEOUT);
    let mut hello = Vec::new();
    timeout(
        Duration::from_secs(2),
        silent_server.read_to_end(&mut hello),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(hello.first(), Some(&0x16));
}
