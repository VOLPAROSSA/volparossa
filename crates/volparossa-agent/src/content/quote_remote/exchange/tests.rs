use super::*;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

#[tokio::test]
async fn quote_confirmation_bridge_selects_only_the_explicit_wire_profile() {
    for (version, selector) in [(None, 1), (Some(1), 2)] {
        let (mut client, mut provider) = tokio::io::duplex(128);
        let exchange = tokio::spawn(async move {
            Exchange::begin(&mut client, &[1; 32], version)
                .await
                .is_err()
        });
        assert_eq!(provider.read_u32().await.unwrap(), 4);
        let mut bytes = [0; 4];
        provider.read_exact(&mut bytes).await.unwrap();
        assert_eq!(bytes, [8, selector, 24, 7]);
        // No signed challenge: EOF rejects instead of reconnecting/falling back.
        drop(provider);
        assert!(exchange.await.unwrap());
    }
}

#[tokio::test]
async fn quote_confirmation_bridge_rejects_unknown_mode_before_remote_bytes() {
    for version in [0, 2, u32::MAX] {
        let (mut client, mut provider) = tokio::io::duplex(128);
        assert!(matches!(
            Exchange::begin(&mut client, &[1; 32], Some(version)).await,
            Err(ContentError::Invalid)
        ));
        drop(client);
        assert_eq!(provider.read(&mut [0; 1]).await.unwrap(), 0);
    }
}

#[tokio::test]
async fn quote_confirmation_bridge_rejects_invalid_remote_challenge_framing() {
    for frame in [
        vec![],
        vec![0, 0, 0],
        vec![0; 4],
        vec![255; 4],
        vec![0, 0, 0, 2, 8, 9],
    ] {
        let (mut client, mut provider) = tokio::io::duplex(128);
        let exchange = tokio::spawn(async move {
            Exchange::begin(&mut client, &[1; 32], Some(1))
                .await
                .is_err()
        });
        assert_eq!(provider.read_u32().await.unwrap(), 4);
        provider.read_exact(&mut [0; 4]).await.unwrap();
        provider.write_all(&frame).await.unwrap();
        drop(provider);
        assert!(exchange.await.unwrap());
    }
}

#[tokio::test]
async fn quote_confirmation_expired_response_never_starts_final_handoff() {
    let expired = Instant::now() - Duration::from_secs(1);
    assert!(check_deadline(Some(expired)).is_err());
    assert!(check_deadline(None).is_ok());
    let mut polled = false;
    assert!(
        finish_before(Some(expired), async {
            polled = true;
            Ok(())
        })
        .await
        .is_err()
    );
    assert!(!polled);
    assert!(finish_before(None, async { Ok(()) }).await.is_ok());
    assert_eq!(
        Response::Legacy(wire::QuoteOutcome::DeviceUnavailable).deadline(),
        None
    );
}

#[tokio::test]
async fn quote_confirmation_late_close_is_bounded_by_original_handoff_deadline() {
    let deadline = Instant::now() + Duration::from_millis(10);
    let result = finish_before(
        Some(deadline),
        std::future::pending::<Result<(), ContentError>>(),
    )
    .await;
    assert!(result.is_err());
    assert!(Instant::now() >= deadline);
    assert!(check_deadline(Some(deadline)).is_err());
}
