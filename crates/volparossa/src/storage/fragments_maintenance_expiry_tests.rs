//! Clock drift across real signed storage exchanges, not protected-overlay evidence.

use super::*;
use crate::storage::peer::diagnostics::{Boundary, Operation as DiagnosticOperation, Stage};
use tokio::{net::UnixListener, sync::oneshot, time::timeout};
use volparossa_content::private_storage::{
    LeaseId,
    protocol::{StorageChallenge, StorageOperation, StorageTarget},
};
use volparossa_local_control::{
    CONTROL_PROTOCOL_VERSION, ControlResponse, PrivateStorageReady, read_request, read_response,
    write_request, write_response,
};

/// Delay the first live Progress challenge. Its signed response still comes from
/// the real `SQLite` provider, as do subsequent Renew/Reserve operations and receipts.
async fn delayed_progress(
    listener: UnixListener,
    backend: PathBuf,
    mut stop: oneshot::Receiver<()>,
) -> u64 {
    let mut delayed = 0;
    loop {
        let mut local = tokio::select! {
            _ = &mut stop => break,
            accepted = listener.accept() => accepted.unwrap().0,
        };
        let request = read_request(&mut local).await.unwrap();
        let mut provider = tokio::net::UnixStream::connect(&backend).await.unwrap();
        write_request(&mut provider, &request).await.unwrap();
        let Ok(response) = read_response(&mut provider).await else {
            continue; // Offline original: retain its actual uncertainty, not a fabricated reply.
        };
        assert_eq!(response.diagnostic_code, "PRIVATE_STORAGE_READY");
        if delayed == 0 {
            let before = crate::storage::now().unwrap();
            tokio::time::sleep(Duration::from_millis(1100)).await;
            delayed = crate::storage::now().unwrap() - before;
            assert!(delayed >= 1);
        }
        write_response(&mut local, &response).await.unwrap();
        tokio::io::copy_bidirectional(&mut local, &mut provider)
            .await
            .unwrap();
    }
    delayed
}

#[allow(
    clippy::too_many_lines,
    reason = "Keep the signed enrollment, delayed real-provider exchange, retained journals and joined cleanup in one lifecycle."
)]
async fn delayed_maintenance(repair_missing: bool) {
    let temp = tempfile::tempdir().unwrap();
    let (owner, mut providers, mut grants) = keys_and_grants(16);
    let (replacement, grant) = candidate(&owner);
    providers.push(replacement);
    grants.push(grant);
    let bytes = vec![31; 3 * CHUNK_BYTES + 9];
    let source = temp.path().join("ciphertext");
    fs::write(&source, &bytes).unwrap();
    let (mut input, _) = transfer::checked_input(&source, plan(&bytes).sha256).unwrap();
    let archive = temp.path().join("fragments");
    let set = LockedFragments::create(
        &archive,
        &owner,
        &mut input,
        plan(&bytes),
        &grants[..3],
        600,
    )
    .unwrap();
    let peers = LocalProviders::start(temp.path(), &providers, &grants, true);
    assert_eq!(
        operations::deposit(&set, &peers.socket, &owner, &mut input)
            .await
            .unwrap()["operation_complete"],
        true
    );
    let original = set.fragment(0).unwrap().copy(0).unwrap().journal.clone();
    let mut enrollment = enrollment(&set, archive.clone(), &owner, &providers, &grants[3]);
    enrollment.expires = crate::storage::now().unwrap() + 900;
    enrollment.lifetime = 1800;
    // Authenticate the exact cap under test, without altering original custody journals.
    let directory = temp.path().join("maintenance");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .unwrap();
    let directory = state::directory(&directory).unwrap();
    let signature = hex::encode(owner.sign(&signing(&enrollment).unwrap()).to_bytes());
    save(
        &directory,
        "enrollment.json",
        &SignedEnrollment {
            enrollment,
            signature,
        },
    )
    .unwrap();
    let enrollment = load(&directory).unwrap();
    drop((set, input));
    fs::remove_file(source).unwrap();
    if repair_missing {
        peers.online[0].store(false, Ordering::SeqCst);
    }
    let socket = temp.path().join("delayed.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let (stop, stopping) = oneshot::channel();
    let server = delayed_progress(listener, peers.socket.clone(), stopping);
    let work = async {
        let result =
            transfer::with_maintenance_turn(vec![8; 32], maintain(&enrollment, &socket, &owner, 0))
                .await
                .unwrap();
        stop.send(()).unwrap();
        result
    };
    let (result, delayed) = timeout(Duration::from_secs(20), async {
        tokio::join!(work, server)
    })
    .await
    .unwrap();
    assert!(delayed >= 1);
    let set = LockedFragments::open(&archive).unwrap();
    let fragment = set.fragment(0).unwrap();
    assert_eq!(
        fragment.copy(0).unwrap().journal.requested_expiry,
        original.requested_expiry
    );
    if repair_missing {
        assert_eq!(result["freshly_verified_replacements"], 1);
        let handoff = fragment.data.handoff.as_ref().unwrap();
        assert_eq!(handoff.initial_journal.requested_expiry, enrollment.expires);
        assert_eq!(
            fragment.copy(handoff.to).unwrap().journal.last_expiry,
            enrollment.expires
        );
        assert_eq!(
            fragment.copy(0).unwrap().journal.last_expiry,
            original.last_expiry
        );
    } else {
        assert_eq!(
            result["refresh"]["copy_outcomes"],
            serde_json::json!(["confirmed", "confirmed"])
        );
        for index in 0..2 {
            assert_eq!(
                fragment.copy(index).unwrap().journal.last_expiry,
                enrollment.expires
            );
        }
    }
    drop((fragment, set));
    peers.stop().await;
}

#[tokio::test]
async fn delayed_progress_renewal_keeps_original_signed_enrollment_expiry() {
    Box::pin(delayed_maintenance(false)).await;
}

#[tokio::test]
async fn repair_after_delayed_refresh_keeps_original_signed_enrollment_expiry() {
    Box::pin(delayed_maintenance(true)).await;
}

#[tokio::test]
async fn expired_cap_cannot_plan_and_foreground_expiry_is_unchanged() {
    let (owner, _, _) = keys_and_grants(16);
    let (_, grant) = candidate(&owner);
    let now = crate::storage::now().unwrap();
    let cap = now + 300;
    transfer::with_maintenance_expiry(cap, async {
        assert_eq!(transfer::requested_expiry(&grant, 900).unwrap(), cap);
    })
    .await;
    let error = transfer::with_maintenance_expiry(now, async {
        transfer::requested_expiry(&grant, 900).unwrap_err()
    })
    .await;
    assert_eq!(error.to_string(), "enrollment_expired");
    let before = crate::storage::now().unwrap();
    let expires = transfer::requested_expiry(&grant, 900).unwrap();
    let after = crate::storage::now().unwrap();
    assert!((before + 900..=after + 900).contains(&expires));
    assert!(expires > cap);
}

async fn rejected_after_challenge(expired: bool, renewal: bool) {
    let temp = tempfile::tempdir().unwrap();
    let (owner, _, _) = keys_and_grants(16);
    let (provider, grant) = candidate(&owner);
    let now = crate::storage::now().unwrap();
    let cap = now + if expired { 1 } else { 300 };
    let target = StorageTarget {
        archive_id: [7; 32],
        lease_id: (expired || renewal).then_some(LeaseId::from_bytes([6; 16])),
        ciphertext_bytes: 8,
        sha256: [9; 32],
    };
    let operation = if expired {
        StorageOperation::Progress
    } else if renewal {
        StorageOperation::Renew {
            expires_at: cap + 1,
        }
    } else {
        StorageOperation::Reserve {
            expires_at: cap + 1,
        }
    };
    let socket = temp.path().join("challenge.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = async {
        let (mut local, _) = listener.accept().await.unwrap();
        let request = read_request(&mut local).await.unwrap();
        let challenge = StorageChallenge::issue(
            &provider,
            &grant,
            Validity {
                created: now,
                expires: now + 60,
            },
        )
        .unwrap();
        if expired {
            tokio::time::sleep(Duration::from_millis(1100)).await;
            assert!(crate::storage::now().unwrap() >= cap);
        }
        write_response(
            &mut local,
            &ControlResponse {
                protocol_version: CONTROL_PROTOCOL_VERSION,
                request_id: request.request_id,
                result: 0,
                diagnostic_code: "PRIVATE_STORAGE_READY".into(),
                private_storage_remote_detail: None,
                payload: Some(Payload::PrivateStorageReady(PrivateStorageReady {
                    provider_key: provider.verifying_key().to_bytes().to_vec(),
                    challenge: challenge.encode(),
                })),
            },
        )
        .await
        .unwrap();
        assert_eq!(
            local.read(&mut [0]).await.unwrap(),
            0,
            "no signed operation after rejection"
        );
    };
    let client = transfer::with_maintenance_expiry(cap, async {
        transfer::remote(&socket, &grant, &owner, target, operation, &[]).await
    });
    let (result, ()) = timeout(Duration::from_secs(5), async {
        tokio::join!(client, server)
    })
    .await
    .unwrap();
    let error = result.err().unwrap();
    let boundary = error.downcast_ref::<Boundary>().unwrap();
    assert!(matches!(boundary.stage, Stage::SignedRequest));
    assert!(matches!(
        (expired, renewal, boundary.operation),
        (true, _, DiagnosticOperation::Progress)
            | (false, true, DiagnosticOperation::Renew)
            | (false, false, DiagnosticOperation::Reserve)
    ));
    assert_eq!(
        error.root_cause().to_string(),
        if expired {
            "enrollment_expired"
        } else {
            "requested lease outlives maintenance enrollment"
        }
    );
}

#[tokio::test]
async fn expired_during_challenge_does_not_sign_any_new_operation() {
    rejected_after_challenge(true, false).await;
}

#[tokio::test]
async fn signing_does_not_rewrite_over_cap_retained_reserve_or_renew() {
    rejected_after_challenge(false, false).await;
    rejected_after_challenge(false, true).await;
}
