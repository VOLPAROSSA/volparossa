use super::*;

pub(super) fn scope(partition_byte: u8) -> Scope {
    Scope {
        uid: 1000,
        hostname: "example.com".into(),
        port: 443,
        partition: [partition_byte; 32],
        policy_hash: [2; 32],
        expires_at_ms: unix_millis() + 60_000,
        deadline: Instant::now() + Duration::from_secs(60),
    }
}

fn gateway() -> BrowserGateway {
    BrowserGateway::new(
        PathBuf::from("/absent/apps.sock"),
        PathBuf::from("/absent/mpquic.sock"),
    )
}

#[tokio::test]
async fn gateway_kernel_uid_partition_expiry_and_single_use_are_required() {
    let gateway = gateway();
    let key = gateway
        .issue(Arc::new(scope(1)))
        .await
        .unwrap_or_else(|_| panic!("scope"));
    assert!(gateway.claim(key, &[1; 32], 1001).await.is_err());
    assert!(gateway.claim(key, &[2; 32], 1000).await.is_err());
    let attachment = gateway
        .claim(key, &[1; 32], 1000)
        .await
        .unwrap_or_else(|_| panic!("claim"));
    assert!(gateway.claim(key, &[1; 32], 1000).await.is_err());
    gateway.retire(&attachment).await.unwrap();
    assert!(gateway.claim(key, &[1; 32], 1000).await.is_err());
    let mut expired = scope(2);
    expired.deadline = Instant::now();
    let key = gateway
        .issue(Arc::new(expired))
        .await
        .unwrap_or_else(|_| panic!("expired scope"));
    assert!(gateway.claim(key, &[2; 32], 1000).await.is_err());
}

#[tokio::test]
async fn gateway_detach_closes_only_its_controller_not_other_apps_or_main_dns() {
    let gateway = gateway();
    let main = ClientRouteControl::new(PathBuf::from("/absent/main.sock"));
    let dns = ClientRouteControl::new(PathBuf::from("/absent/dns.sock"));
    let key_a = gateway
        .issue(Arc::new(scope(1)))
        .await
        .unwrap_or_else(|_| panic!("A"));
    let key_b = gateway
        .issue(Arc::new(scope(2)))
        .await
        .unwrap_or_else(|_| panic!("B"));
    let a = gateway
        .claim(key_a, &[1; 32], 1000)
        .await
        .unwrap_or_else(|_| panic!("claim A"));
    let b = gateway
        .claim(key_b, &[2; 32], 1000)
        .await
        .unwrap_or_else(|_| panic!("claim B"));
    assert_ne!(a.proxy_secret, b.proxy_secret);
    gateway.retire(&a).await.unwrap();
    assert!(a.routes.admission_closed_for_test().await);
    assert!(!b.routes.admission_closed_for_test().await);
    assert!(!main.admission_closed_for_test().await);
    assert!(!dns.admission_closed_for_test().await);
    assert!(!gateway.grants.lock().await.contains_key(&grant_id(&key_a)));
    assert!(gateway.grants.lock().await.contains_key(&grant_id(&key_b)));
    gateway.retire(&b).await.unwrap();
    assert!(b.routes.admission_closed_for_test().await);
    assert!(gateway.grants.lock().await.is_empty());
    // These are actual controller-lifecycle assertions, not live overlay throughput evidence.
}

#[tokio::test]
async fn gateway_issued_and_claimed_scopes_share_one_finite_admission_bound() {
    let gateway = gateway();
    for index in 0..MAX_ATTACHMENTS {
        let key = gateway
            .issue(Arc::new(scope(1)))
            .await
            .unwrap_or_else(|_| panic!("bounded grant"));
        if index % 2 == 0 {
            let _ = gateway
                .claim(key, &[1; 32], 1000)
                .await
                .unwrap_or_else(|_| panic!("claim"));
        }
    }
    assert!(matches!(
        gateway.issue(Arc::new(scope(1))).await,
        Err(GatewayError::Busy)
    ));
    gateway.shutdown_confirmed().await.unwrap();
    assert!(gateway.grants.lock().await.is_empty());
}
