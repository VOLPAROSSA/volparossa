use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;
use crate::{
    provider::{PublicationRegistry, serve_publication},
    transfer::TransferLimits,
};

// Transport fixture only; never a successful model execution, lease or capability proof.
struct Echo {
    requester: [u8; 32],
    calls: AtomicUsize,
}

impl ComputeBackend for Echo {
    fn exchange(&self, requester: [u8; 32], request: Vec<u8>) -> ComputeFuture<'_> {
        Box::pin(async move {
            assert_eq!(requester, self.requester);
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(request)
        })
    }
}

#[tokio::test]
async fn provider_selector_carries_exact_signed_short_exchange_not_model_execution() {
    let provider = Arc::new(SigningKey::from_bytes(&[1; 32]));
    let requester = SigningKey::from_bytes(&[2; 32]);
    let backend = Arc::new(Echo {
        requester: requester.verifying_key().to_bytes(),
        calls: AtomicUsize::new(0),
    });
    let mut registry = PublicationRegistry::new();
    assert!(!registry.has_compute());
    registry.set_compute(Arc::new(ComputeService::new(
        Arc::clone(&provider),
        backend.clone(),
    )));
    let (mut client, mut server) = tokio::io::duplex(4096);
    let serving = serve_publication(&mut server, &registry, TransferLimits::default());
    let requesting = async {
        let challenge = begin(&mut client, &provider.verifying_key().to_bytes())
            .await
            .unwrap();
        exchange(
            &mut client,
            challenge,
            &requester,
            b"bounded transport fixture".to_vec(),
        )
        .await
        .unwrap()
    };
    let (server_result, reply) = tokio::join!(serving, requesting);
    assert!(server_result.is_ok());
    assert_eq!(reply, b"bounded transport fixture");
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn signatures_canonical_shape_original_expiry_and_other_stream_replay_are_checked() {
    let provider = SigningKey::from_bytes(&[1; 32]);
    let requester = SigningKey::from_bytes(&[2; 32]);
    let challenge = Record::challenge(&provider, 100).unwrap();
    let other = Record::challenge(&provider, 100).unwrap();
    let request = Record::request(&requester, &challenge, b"poll".to_vec(), 101).unwrap();
    let bytes = request.encode();
    let decoded = Record::decode(&bytes, Kind::Request, 102).unwrap();
    assert_eq!(decoded.sender(), requester.verifying_key().to_bytes());
    assert!(decoded.matches_challenge(&challenge).is_ok());
    assert!(matches!(
        decoded.matches_challenge(&other),
        Err(ComputeError::Authentication)
    ));
    assert!(matches!(
        Record::decode(&bytes, Kind::Request, 130),
        Err(ComputeError::Expired)
    ));
    assert!(Record::decode(&bytes, Kind::Reply, 102).is_err());
    let mut changed = bytes.clone();
    let last = changed.len() - 1;
    changed[last] ^= 1;
    assert!(Record::decode(&changed, Kind::Request, 102).is_err());
    let mut extended = bytes;
    extended.extend_from_slice(&[0x18, 0x01]);
    assert!(Record::decode(&extended, Kind::Request, 102).is_err());
    assert!(Record::request(&requester, &challenge, vec![0; MAX_REQUEST_BYTES + 1], 101).is_err());
}

#[tokio::test]
async fn absent_compute_service_does_not_fall_back_to_content_or_another_protocol() {
    let registry = PublicationRegistry::new();
    let provider = SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes();
    let (mut client, mut server) = tokio::io::duplex(4096);
    let serving = async {
        let result = serve_publication(&mut server, &registry, TransferLimits::default()).await;
        drop(server);
        result
    };
    let (server_result, started) = tokio::join!(serving, begin(&mut client, &provider));
    assert!(matches!(
        server_result,
        Err(super::super::ProviderError::Missing)
    ));
    assert!(started.is_err());
}
