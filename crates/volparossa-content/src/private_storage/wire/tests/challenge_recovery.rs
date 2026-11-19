use super::*;
use crate::private_storage::wire::begin_observation::Unobserved;

const IDLE: Duration = Duration::from_secs(3);

async fn begin_first(
    stream: &mut DuplexStream,
    fixture: &Fixture,
) -> Result<Option<StorageChallenge>, WireError> {
    let limit = ChallengeIdleLimit {
        idle: IDLE,
        retry_before: tokio::time::Instant::now() + Duration::from_secs(60),
    };
    begin_observed_with_idle_limit(stream, &fixture.grant, &Unobserved, Some(limit)).await
}

fn challenge(fixture: &Fixture) -> StorageChallenge {
    let now = unix_now().unwrap();
    StorageChallenge::issue(
        &fixture.signer,
        &fixture.grant,
        Validity {
            created: now,
            expires: now + 60,
        },
    )
    .unwrap()
}

#[tokio::test(start_paused = true)]
async fn a_stalled_challenge_read_alone_returns_an_idle_result() {
    let fixture = Fixture::new();
    let empty = fixture.usage();
    for partial in [&[][..], &[0, 0][..], &[0, 0, 0, 3, 1][..]] {
        let (mut client, mut peer) = tokio::io::duplex(4096);
        peer.write_all(partial).await.unwrap();
        let started = tokio::time::Instant::now();
        let result = begin_first(&mut client, &fixture).await.unwrap();
        assert!(result.is_none());
        assert!(started.elapsed() >= IDLE && started.elapsed() < IO_TIMEOUT);
        drop(client);
        let selector = read_frame(&mut peer, 64).await.unwrap();
        assert_eq!(
            Selector::decode(selector.as_slice()).unwrap().operation,
            SELECTOR_OPERATION
        );
        assert_eq!(
            read_frame(&mut peer, MAX_GRANT_BYTES).await.unwrap(),
            fixture.grant.signed().encode()
        );
        assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
    }
    let (mut client, _silent_peer) = tokio::io::duplex(4096);
    let result =
        begin_observed_with_idle_limit(&mut client, &fixture.grant, &Unobserved, None).await;
    assert!(matches!(result, Err(WireError::Timeout)));
    let (mut client, _blocked_peer) = tokio::io::duplex(1);
    let result = begin_first(&mut client, &fixture).await;
    assert!(matches!(result, Err(WireError::Timeout)));
    assert_eq!(fixture.usage(), empty);
}

#[tokio::test(start_paused = true)]
async fn slow_progress_in_both_header_and_signed_body_keeps_the_original_challenge() {
    let fixture = Fixture::new();
    let expected = challenge(&fixture);
    let body = expected.encode();
    let header = u32::try_from(body.len()).unwrap().to_be_bytes();
    let (mut client, mut peer) = tokio::io::duplex(4096);
    let send = async {
        for byte in header {
            tokio::time::sleep(Duration::from_secs(2)).await;
            peer.write_all(&[byte]).await.unwrap();
        }
        for chunk in body.chunks(body.len().div_ceil(4)) {
            tokio::time::sleep(Duration::from_secs(2)).await;
            peer.write_all(chunk).await.unwrap();
        }
    };
    let receive = begin_first(&mut client, &fixture);
    let started = tokio::time::Instant::now();
    let ((), received) = tokio::join!(send, receive);
    assert!(started.elapsed() >= Duration::from_secs(16));
    assert_eq!(received.unwrap().unwrap().id(), expected.id());
}

#[tokio::test(start_paused = true)]
async fn partial_eof_invalid_length_and_bad_signature_are_terminal() {
    let fixture = Fixture::new();
    for partial in [&[0, 0][..], &[0, 0, 0, 3, 1][..]] {
        let (mut client, mut peer) = tokio::io::duplex(4096);
        peer.write_all(partial).await.unwrap();
        peer.shutdown().await.unwrap();
        let result = begin_first(&mut client, &fixture).await;
        assert!(
            matches!(result, Err(WireError::Io(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof)
        );
    }
    let (mut client, mut peer) = tokio::io::duplex(4096);
    peer.write_u32(u32::try_from(MAX_CHALLENGE_BYTES + 1).unwrap())
        .await
        .unwrap();
    let result = begin_first(&mut client, &fixture).await;
    assert!(matches!(result, Err(WireError::Invalid)));

    let signed = challenge(&fixture).encode();
    let mut envelope = RawEnvelope::decode(signed.as_slice()).unwrap();
    envelope.signature[0] ^= 1;
    let (mut client, mut peer) = tokio::io::duplex(4096);
    write_frame(&mut peer, &envelope.encode_to_vec())
        .await
        .unwrap();
    let result = begin_first(&mut client, &fixture).await;
    assert!(matches!(
        result,
        Err(WireError::Protocol(ProtocolError::Unauthorized))
    ));
    assert_eq!(fixture.usage().leases, 0);
}

#[tokio::test(start_paused = true)]
async fn read_progress_into_the_final_window_keeps_the_same_connection() {
    let fixture = Fixture::new();
    let expected = challenge(&fixture);
    let body = expected.encode();
    let (mut client, mut peer) = tokio::io::duplex(4096);
    let limit = ChallengeIdleLimit {
        idle: IDLE,
        retry_before: tokio::time::Instant::now() + Duration::from_secs(4),
    };
    let send = async {
        tokio::time::sleep(Duration::from_secs(2)).await;
        peer.write_u32(u32::try_from(body.len()).unwrap())
            .await
            .unwrap();
        tokio::time::sleep(IDLE * 2).await;
        peer.write_all(&body).await.unwrap();
    };
    let receive =
        begin_observed_with_idle_limit(&mut client, &fixture.grant, &Unobserved, Some(limit));
    let ((), received) = tokio::join!(send, receive);
    assert_eq!(received.unwrap().unwrap().id(), expected.id());
}

#[tokio::test(start_paused = true)]
async fn a_fresh_provider_connection_reserves_the_original_target_exactly_once() {
    let fixture = Fixture::new();
    let original = target(b"opaque retained ciphertext");
    let expires_at = unix_now().unwrap() + 600;
    let (mut first, mut peer) = tokio::io::duplex(4096);
    let (mut provider, first_server) = fixture.stream();
    let withhold_challenge = async {
        let selector = read_frame(&mut peer, 64).await.unwrap();
        let grant = read_frame(&mut peer, MAX_GRANT_BYTES).await.unwrap();
        assert_eq!(grant, fixture.grant.signed().encode());
        write_frame(&mut provider, &selector).await.unwrap();
        write_frame(&mut provider, &grant).await.unwrap();
        let encoded = read_frame(&mut provider, MAX_CHALLENGE_BYTES)
            .await
            .unwrap();
        let withheld =
            StorageChallenge::decode_and_verify(&encoded, &fixture.grant, unix_now().unwrap())
                .unwrap();
        assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
        drop(provider);
        withheld
    };
    let cancel = async {
        assert!(begin_first(&mut first, &fixture).await.unwrap().is_none());
        drop(first);
    };
    let (withheld, ()) = tokio::join!(withhold_challenge, cancel);
    assert!(first_server.await.unwrap().is_err());
    assert_eq!(fixture.usage().leases, 0);

    // The simulated idle deadline is past. Let real SQLite blocking work complete on real time.
    tokio::time::resume();
    let (mut fresh, server) = fixture.stream();
    let challenge = begin_observed_with_idle_limit(&mut fresh, &fixture.grant, &Unobserved, None)
        .await
        .unwrap()
        .unwrap();
    assert_ne!(challenge.id(), withheld.id());
    let request = fixture.request(
        &challenge,
        original,
        StorageOperation::Reserve { expires_at },
    );
    let response = finish(&mut fresh, &fixture.grant, &challenge, &request, &[])
        .await
        .unwrap();
    drop(fresh);
    server.await.unwrap().unwrap();
    assert_eq!(response.receipt.result().state, ReceiptState::Reserved);
    assert_eq!(response.receipt.result().expires_at, expires_at);
    assert_eq!(
        fixture.usage(),
        StorageUsage {
            reserved_bytes: original.ciphertext_bytes,
            committed_bytes: 0,
            leases: 1
        }
    );
}
