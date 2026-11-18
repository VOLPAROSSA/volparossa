use super::*;
use volparossa_local_control::{CONTROL_PROTOCOL_VERSION, ControlResult, Empty};

fn terminal() -> ControlResponse {
    ControlResponse {
        protocol_version: CONTROL_PROTOCOL_VERSION,
        request_id: vec![1; 16],
        result: ControlResult::Ok.into(),
        diagnostic_code: "QUOTE_KEY_CONFIRMED".into(),
        private_storage_remote_detail: None,
        payload: Some(Payload::Ack(Empty {})),
    }
}

#[test]
fn quote_confirmation_report_adds_possession_but_no_admission_or_appraisal() {
    let report = VerifyReport::Confirmed(Report {
        version: 3,
        quote_exchange: true,
        bound_reference_evidence: true,
        key_confirmation: true,
        complete_appraisal: false,
        worker_admission: false,
        private_input_released: false,
        outstanding_appraisal: vec![
            "production_root_authorization",
            "vcek_revocation_and_collateral_freshness",
            "vendor_tcb_and_local_policy",
            "authorized_workload_and_key_origin",
        ],
    });
    assert!(report.require_evidence().is_ok());
    assert_eq!(
        serde_json::to_value(report).unwrap(),
        serde_json::json!({
            "version": 3,
            "quote_exchange": true,
            "bound_reference_evidence": true,
            "key_confirmation": true,
            "complete_appraisal": false,
            "worker_admission": false,
            "private_input_released": false,
            "outstanding_appraisal": [
                "production_root_authorization",
                "vcek_revocation_and_collateral_freshness",
                "vendor_tcb_and_local_policy",
                "authorized_workload_and_key_origin",
            ],
        })
    );
}

#[test]
fn quote_confirmation_requires_its_own_final_ack_not_legacy_success() {
    let mut finished = terminal();
    assert!(check_terminal(&finished, false).is_ok());
    assert!(check_terminal(&finished, true).is_err());
    for code in [
        "QUOTE_EXCHANGE_OK",
        "QUOTE_READY",
        "QUOTE_DEVICE_UNAVAILABLE",
        "",
    ] {
        finished.diagnostic_code = code.into();
        assert!(check_terminal(&finished, false).is_err());
    }
    finished.diagnostic_code = "QUOTE_DEVICE_UNAVAILABLE".into();
    assert!(check_terminal(&finished, true).is_ok());
    finished.payload = None;
    assert!(check_terminal(&finished, true).is_err());
    finished.diagnostic_code = "QUOTE_KEY_CONFIRMED".into();
    assert!(check_terminal(&finished, false).is_err());
}

#[tokio::test]
async fn quote_confirmation_final_ack_requires_original_correlation_and_ok_result() {
    for (id, result, valid) in [
        (vec![1; 16], ControlResult::Ok, true),
        (vec![2; 16], ControlResult::Ok, false),
        (vec![1; 16], ControlResult::Unavailable, false),
    ] {
        let (mut client, mut agent) = UnixStream::pair().unwrap();
        let mut response = terminal();
        response.request_id = id;
        response.result = result.into();
        volparossa_local_control::write_response(&mut agent, &response)
            .await
            .unwrap();
        let received = finish(
            &mut client,
            &[1; 16],
            Instant::now() + std::time::Duration::from_secs(1),
            false,
        )
        .await;
        assert_eq!(received.is_ok(), valid);
    }
}

#[tokio::test(start_paused = true)]
async fn quote_confirmation_final_ack_cannot_refresh_original_deadline() {
    let (mut client, _agent) = UnixStream::pair().unwrap();
    let start = Instant::now();
    let deadline = start + std::time::Duration::from_secs(3);
    tokio::time::advance(std::time::Duration::from_secs(2)).await;
    assert!(
        finish(&mut client, &[1; 16], deadline, false)
            .await
            .is_err()
    );
    assert_eq!(Instant::now(), deadline);
}

#[tokio::test]
async fn quote_confirmation_owner_continuation_rejects_bad_offer_before_any_probe() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use volparossa_content::provider::compute::attestation::{
        LocalPolicy, MilanTcb, SessionLimits, SessionOwner, SmtPolicy, TcbMinimums,
    };

    for frame in [vec![], vec![0; 4], vec![255; 4], vec![0, 0, 0, 2, 8, 9]] {
        let tcb = MilanTcb {
            bootloader: 1,
            tee: 1,
            snp: 1,
            microcode: 1,
        };
        let policy = LocalPolicy::new(
            [2; 48],
            0,
            TcbMinimums {
                current: tcb,
                reported: tcb,
                committed: tcb,
                launch: tcb,
            },
            SmtPolicy::RequireDisabled,
        )
        .unwrap();
        let owner = SessionOwner::new(
            [1; 32],
            policy,
            SessionLimits {
                expires_at: super::super::now().unwrap() + 30,
                maximum_pending: 1,
                maximum_attempts: 1,
            },
        )
        .unwrap();
        let ready = QuoteReady {
            provider_key: vec![1; 32],
            requester_key: vec![2; 32],
            confirmation_version: Some(1),
        };
        let (mut client, mut agent) = UnixStream::pair().unwrap();
        let operation = verify(
            &ready,
            owner.begin().unwrap(),
            &mut client,
            &[1; 16],
            &[1],
            &[2],
        );
        let peer = async {
            // Exercise the real first owner-request write and bounded offer parser.
            super::super::wire::read_request(&mut agent).await.unwrap();
            agent.write_all(&frame).await.unwrap();
            agent.shutdown().await.unwrap();
        };
        let (result, ()) = tokio::join!(operation, peer);
        assert!(result.is_err());
        drop(client);
        assert_eq!(agent.read(&mut [0; 1]).await.unwrap(), 0);
        // This failed one-use owner attempt is not refunded.
        assert!(owner.begin().is_err());
    }
}
